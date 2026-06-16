package subscriptionexport

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Resinat/Resin/internal/config"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/topology"

	"gopkg.in/yaml.v3"
)

const (
	ContentTypeSingbox = "application/json; charset=utf-8"
	ContentTypeClash   = "application/x-yaml; charset=utf-8"
)

type runtimeConfigProvider interface {
	Load() *config.RuntimeConfig
}

// Config wires the healthy-node subscription exporter to the existing pool and
// runtime config. The exporter only reads current node state; it never triggers
// probes or health scans.
type Config struct {
	Pool       *topology.GlobalNodePool
	RuntimeCfg runtimeConfigProvider
	Now        func() time.Time
}

// Exporter builds and caches the healthy encrypted-node sing-box subscription.
type Exporter struct {
	pool       *topology.GlobalNodePool
	runtimeCfg runtimeConfigProvider
	now        func() time.Time

	mu       sync.RWMutex
	snapshot Snapshot

	running atomic.Bool
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// Snapshot is the current export cache plus generation metadata.
type Snapshot struct {
	Enabled          bool      `json:"enabled"`
	ContentType      string    `json:"content_type"`
	NodeCount        int       `json:"node_count"`
	ClashNodeCount   int       `json:"clash_node_count"`
	GeneratedAt      time.Time `json:"generated_at,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
	RefreshInterval  string    `json:"refresh_interval"`
	SubscriptionPath string    `json:"subscription_path"`
	Content          []byte    `json:"-"`
	ClashContent     []byte    `json:"-"`
}

type singboxSubscription struct {
	Outbounds []json.RawMessage `json:"outbounds"`
}

type outboundHeader struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
}

type exportCandidate struct {
	Hash node.Hash
	Raw  json.RawMessage
}

type clashSubscription struct {
	Proxies []map[string]any `yaml:"proxies"`
}

// NewExporter creates a healthy-node subscription exporter.
func NewExporter(cfg Config) *Exporter {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Exporter{
		pool:       cfg.Pool,
		runtimeCfg: cfg.RuntimeCfg,
		now:        now,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
}

// Start begins the periodic cache refresh loop.
func (e *Exporter) Start() {
	if e == nil || !e.running.CompareAndSwap(false, true) {
		return
	}
	go e.run()
}

// Stop terminates the periodic cache refresh loop.
func (e *Exporter) Stop() {
	if e == nil || !e.running.CompareAndSwap(true, false) {
		return
	}
	close(e.stopCh)
	<-e.doneCh
}

func (e *Exporter) run() {
	defer close(e.doneCh)
	e.Refresh(context.Background())
	for {
		interval := e.currentRefreshInterval()
		if interval <= 0 {
			interval = time.Minute
		}
		timer := time.NewTimer(interval)
		select {
		case <-e.stopCh:
			timer.Stop()
			return
		case <-timer.C:
			e.Refresh(context.Background())
		}
	}
}

// Snapshot returns a copy of the current cache metadata and content bytes.
func (e *Exporter) Snapshot() Snapshot {
	if e == nil {
		return Snapshot{ContentType: ContentTypeSingbox, SubscriptionPath: SubscriptionPath}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.decorateSnapshot(cloneSnapshot(e.snapshot))
}

// Content returns generated subscription bytes for the requested format. It
// refreshes once when the cache is empty, using the same read-only generation
// path as the periodic updater.
func (e *Exporter) Content(ctx context.Context, format Format) (Snapshot, []byte) {
	snapshot := e.CurrentOrRefresh(ctx)
	return snapshot, snapshot.contentForFormat(format)
}

// Refresh rebuilds the cached subscription from current pool state.
func (e *Exporter) Refresh(ctx context.Context) Snapshot {
	if e == nil {
		return Snapshot{ContentType: ContentTypeSingbox, SubscriptionPath: SubscriptionPath}
	}
	snapshot, err := e.buildSnapshot(ctx)
	if err != nil {
		snapshot.LastError = err.Error()
	}
	e.mu.Lock()
	e.snapshot = cloneSnapshot(snapshot)
	e.mu.Unlock()
	return snapshot
}

// CurrentOrRefresh returns the cached subscription; when no content has been
// generated yet, it performs one read-only generation pass.
func (e *Exporter) CurrentOrRefresh(ctx context.Context) Snapshot {
	snapshot := e.Snapshot()
	if len(snapshot.Content) > 0 || snapshot.LastError != "" || !snapshot.Enabled {
		return snapshot
	}
	return e.Refresh(ctx)
}

// ValidateToken verifies the public subscription token from runtime config.
func (e *Exporter) ValidateToken(token string) bool {
	cfg := e.currentConfig()
	if cfg == nil || !cfg.HealthyNodeSubscriptionEnabled {
		return false
	}
	expected := strings.TrimSpace(cfg.HealthyNodeSubscriptionToken)
	if expected == "" || token == "" {
		return false
	}
	if len(token) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

func (e *Exporter) buildSnapshot(ctx context.Context) (Snapshot, error) {
	cfg := e.currentConfig()
	enabled := cfg != nil && cfg.HealthyNodeSubscriptionEnabled
	snapshot := Snapshot{
		Enabled:          enabled,
		ContentType:      ContentTypeSingbox,
		RefreshInterval:  e.currentRefreshInterval().String(),
		SubscriptionPath: SubscriptionPath,
	}
	if !enabled {
		return snapshot, nil
	}

	select {
	case <-ctx.Done():
		return snapshot, ctx.Err()
	default:
	}

	candidates := e.collectCandidates()
	outbounds := make([]json.RawMessage, 0, len(candidates))
	for _, candidate := range candidates {
		raw := make(json.RawMessage, len(candidate.Raw))
		copy(raw, candidate.Raw)
		outbounds = append(outbounds, raw)
	}

	singboxData, err := json.MarshalIndent(singboxSubscription{Outbounds: outbounds}, "", "  ")
	if err != nil {
		return snapshot, err
	}
	singboxData = append(singboxData, '\n')

	clashProxies := make([]map[string]any, 0, len(candidates))
	usedClashNames := make(map[string]int, len(candidates))
	for _, candidate := range candidates {
		proxy, ok := convertSingboxOutboundToClash(candidate.Raw)
		if ok {
			suffix := candidate.Hash.Hex()
			if len(suffix) > 8 {
				suffix = suffix[:8]
			}
			ensureUniqueClashName(proxy, usedClashNames, suffix)
			clashProxies = append(clashProxies, proxy)
		}
	}
	clashData, err := yaml.Marshal(clashSubscription{Proxies: clashProxies})
	if err != nil {
		return snapshot, err
	}

	snapshot.Content = singboxData
	snapshot.ClashContent = clashData
	snapshot.NodeCount = len(outbounds)
	snapshot.ClashNodeCount = len(clashProxies)
	snapshot.GeneratedAt = e.now().UTC()
	return snapshot, nil
}

func (e *Exporter) collectCandidates() []exportCandidate {
	if e == nil || e.pool == nil {
		return nil
	}
	isHealthyAndEnabled := e.pool.MakeHealthyAndEnabledEvaluator()
	var candidates []exportCandidate
	e.pool.Range(func(h node.Hash, entry *node.NodeEntry) bool {
		if entry == nil || !isHealthyAndEnabled(entry) || !isEncryptedOutbound(entry.RawOptions) {
			return true
		}
		raw := make(json.RawMessage, len(entry.RawOptions))
		copy(raw, entry.RawOptions)
		candidates = append(candidates, exportCandidate{Hash: h, Raw: raw})
		return true
	})
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Hash.Hex() < candidates[j].Hash.Hex()
	})
	return candidates
}

func isEncryptedOutbound(raw json.RawMessage) bool {
	var header outboundHeader
	if err := json.Unmarshal(raw, &header); err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(header.Type)) {
	case "", "socks", "http":
		return false
	default:
		return true
	}
}

func (e *Exporter) currentConfig() *config.RuntimeConfig {
	if e == nil || e.runtimeCfg == nil {
		return config.NewDefaultRuntimeConfig()
	}
	cfg := e.runtimeCfg.Load()
	if cfg == nil {
		return config.NewDefaultRuntimeConfig()
	}
	return cfg
}

func (e *Exporter) currentRefreshInterval() time.Duration {
	cfg := e.currentConfig()
	if cfg == nil {
		return 5 * time.Minute
	}
	return time.Duration(cfg.HealthyNodeSubscriptionRefreshInterval)
}

func (e *Exporter) decorateSnapshot(snapshot Snapshot) Snapshot {
	cfg := e.currentConfig()
	snapshot.Enabled = cfg != nil && cfg.HealthyNodeSubscriptionEnabled
	snapshot.ContentType = ContentTypeSingbox
	snapshot.RefreshInterval = e.currentRefreshInterval().String()
	snapshot.SubscriptionPath = SubscriptionPath
	return snapshot
}

func (s Snapshot) contentForFormat(format Format) []byte {
	switch format {
	case FormatClash:
		return cloneBytes(s.ClashContent)
	default:
		return cloneBytes(s.Content)
	}
}

func cloneSnapshot(in Snapshot) Snapshot {
	out := in
	out.Content = cloneBytes(in.Content)
	out.ClashContent = cloneBytes(in.ClashContent)
	return out
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
