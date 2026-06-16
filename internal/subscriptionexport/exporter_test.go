package subscriptionexport

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/config"
	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/subscription"
	"github.com/Resinat/Resin/internal/testutil"
	"github.com/Resinat/Resin/internal/topology"

	"gopkg.in/yaml.v3"
)

func newExporterTestPool(subMgr *topology.SubscriptionManager) *topology.GlobalNodePool {
	return topology.NewGlobalNodePool(topology.PoolConfig{
		SubLookup:              subMgr.Lookup,
		GeoLookup:              func(netip.Addr) string { return "us" },
		MaxLatencyTableEntries: 16,
		MaxConsecutiveFailures: func() int { return 3 },
		LatencyDecayWindow:     func() time.Duration { return 10 * time.Minute },
	})
}

func addExportTestNode(
	t *testing.T,
	pool *topology.GlobalNodePool,
	sub *subscription.Subscription,
	raw string,
	healthy bool,
) node.Hash {
	t.Helper()
	hash := node.HashFromRawOptions([]byte(raw))
	pool.AddNodeFromSub(hash, []byte(raw), sub.ID)
	sub.ManagedNodes().StoreNode(hash, subscription.ManagedNode{Tags: []string{"tag"}})
	entry, ok := pool.GetEntry(hash)
	if !ok {
		t.Fatalf("node %s missing after add", hash.Hex())
	}
	if healthy {
		ob := testutil.NewNoopOutbound()
		entry.Outbound.Store(&ob)
		pool.RecordResult(hash, true)
	}
	return hash
}

func TestExporterRefresh_UsesCurrentHealthAndExcludesPlainProxyTypes(t *testing.T) {
	subMgr := topology.NewSubscriptionManager()
	pool := newExporterTestPool(subMgr)
	cfgPtr := &atomic.Pointer[config.RuntimeConfig]{}
	cfg := config.NewDefaultRuntimeConfig()
	cfg.HealthyNodeSubscriptionEnabled = true
	cfg.HealthyNodeSubscriptionToken = "export-token"
	cfg.HealthyNodeSubscriptionRefreshInterval = config.Duration(5 * time.Minute)
	cfgPtr.Store(cfg)

	sub := subscription.NewSubscription("sub-a", "sub-a", "https://example.com/a", true, false)
	subMgr.Register(sub)

	ssHash := addExportTestNode(t, pool, sub, `{"type":"shadowsocks","tag":"ss","server":"1.1.1.1","server_port":443,"method":"2022-blake3-aes-128-gcm","password":"secret"}`, true)
	_ = addExportTestNode(t, pool, sub, `{"type":"socks","tag":"socks","server":"2.2.2.2","server_port":1080}`, true)
	_ = addExportTestNode(t, pool, sub, `{"type":"http","tag":"http","server":"3.3.3.3","server_port":8080}`, true)
	_ = addExportTestNode(t, pool, sub, `{"type":"trojan","tag":"broken","server":"4.4.4.4","server_port":443}`, false)

	exporter := NewExporter(Config{
		Pool:       pool,
		RuntimeCfg: cfgPtr,
		Now:        func() time.Time { return time.Date(2026, 6, 17, 1, 2, 3, 0, time.UTC) },
	})
	snapshot := exporter.Refresh(context.Background())
	if snapshot.LastError != "" {
		t.Fatalf("Refresh LastError = %q", snapshot.LastError)
	}
	if snapshot.NodeCount != 1 {
		t.Fatalf("NodeCount = %d, want 1", snapshot.NodeCount)
	}
	if snapshot.GeneratedAt.IsZero() {
		t.Fatal("GeneratedAt should be set")
	}

	var body singboxSubscription
	if err := json.Unmarshal(snapshot.Content, &body); err != nil {
		t.Fatalf("unmarshal export: %v body=%s", err, string(snapshot.Content))
	}
	if len(body.Outbounds) != 1 {
		t.Fatalf("outbounds len = %d, want 1", len(body.Outbounds))
	}
	gotHash := node.HashFromRawOptions(body.Outbounds[0])
	if gotHash != ssHash {
		t.Fatalf("exported hash = %s, want %s", gotHash.Hex(), ssHash.Hex())
	}

	var clashBody struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(snapshot.ClashContent, &clashBody); err != nil {
		t.Fatalf("unmarshal clash export: %v body=%s", err, string(snapshot.ClashContent))
	}
	if len(clashBody.Proxies) != 1 {
		t.Fatalf("clash proxies len = %d, want 1 body=%s", len(clashBody.Proxies), string(snapshot.ClashContent))
	}
	if clashBody.Proxies[0]["type"] != "ss" {
		t.Fatalf("clash proxy type = %v, want ss", clashBody.Proxies[0]["type"])
	}
	if clashBody.Proxies[0]["name"] != "ss" {
		t.Fatalf("clash proxy name = %v, want ss", clashBody.Proxies[0]["name"])
	}
	if snapshot.ClashNodeCount != 1 {
		t.Fatalf("ClashNodeCount = %d, want 1", snapshot.ClashNodeCount)
	}
}

func TestExporterRefresh_ClashOutputCanBeParsedAsSubscription(t *testing.T) {
	subMgr := topology.NewSubscriptionManager()
	pool := newExporterTestPool(subMgr)
	cfgPtr := &atomic.Pointer[config.RuntimeConfig]{}
	cfg := config.NewDefaultRuntimeConfig()
	cfg.HealthyNodeSubscriptionEnabled = true
	cfg.HealthyNodeSubscriptionToken = "export-token"
	cfg.HealthyNodeSubscriptionRefreshInterval = config.Duration(5 * time.Minute)
	cfgPtr.Store(cfg)

	sub := subscription.NewSubscription("sub-a", "sub-a", "https://example.com/a", true, false)
	subMgr.Register(sub)

	vlessRaw := `{
		"type":"vless",
		"tag":"vless-reality",
		"server":"example.com",
		"server_port":443,
		"uuid":"11111111-1111-1111-1111-111111111111",
		"flow":"xtls-rprx-vision",
		"tls":{
			"enabled":true,
			"server_name":"www.example.com",
			"utls":{"enabled":true,"fingerprint":"chrome"},
			"reality":{"enabled":true,"public_key":"pub","short_id":"sid"}
		}
	}`
	vmessRaw := `{
		"type":"vmess",
		"tag":"vmess-ws",
		"server":"vmess.example.com",
		"server_port":443,
		"uuid":"22222222-2222-2222-2222-222222222222",
		"security":"auto",
		"alter_id":0,
		"tls":{"enabled":true,"server_name":"vmess.example.com"},
		"transport":{"type":"ws","path":"/ws","headers":{"Host":"vmess.example.com"}}
	}`
	vlessHash := addExportTestNode(t, pool, sub, vlessRaw, true)
	vmessHash := addExportTestNode(t, pool, sub, vmessRaw, true)

	exporter := NewExporter(Config{Pool: pool, RuntimeCfg: cfgPtr})
	snapshot := exporter.Refresh(context.Background())
	if snapshot.LastError != "" {
		t.Fatalf("Refresh LastError = %q", snapshot.LastError)
	}
	if snapshot.NodeCount != 2 || snapshot.ClashNodeCount != 2 {
		t.Fatalf("counts = singbox:%d clash:%d, want 2/2", snapshot.NodeCount, snapshot.ClashNodeCount)
	}

	parsedNodes, err := subscription.ParseGeneralSubscription(snapshot.ClashContent)
	if err != nil {
		t.Fatalf("ParseGeneralSubscription(clash): %v body=%s", err, string(snapshot.ClashContent))
	}
	if len(parsedNodes) != 2 {
		t.Fatalf("parsed nodes len = %d, want 2 body=%s", len(parsedNodes), string(snapshot.ClashContent))
	}
	got := make(map[node.Hash]bool, len(parsedNodes))
	for _, parsed := range parsedNodes {
		got[node.HashFromRawOptions(parsed.RawOptions)] = true
	}
	if !got[vlessHash] {
		t.Fatalf("parsed clash output missing vless hash %s body=%s", vlessHash.Hex(), string(snapshot.ClashContent))
	}
	if !got[vmessHash] {
		t.Fatalf("parsed clash output missing vmess hash %s body=%s", vmessHash.Hex(), string(snapshot.ClashContent))
	}
}

func TestExporterRefresh_ExcludesDisabledSubscriptionNodes(t *testing.T) {
	subMgr := topology.NewSubscriptionManager()
	pool := newExporterTestPool(subMgr)
	cfgPtr := &atomic.Pointer[config.RuntimeConfig]{}
	cfg := config.NewDefaultRuntimeConfig()
	cfg.HealthyNodeSubscriptionEnabled = true
	cfg.HealthyNodeSubscriptionToken = "export-token"
	cfg.HealthyNodeSubscriptionRefreshInterval = config.Duration(5 * time.Minute)
	cfgPtr.Store(cfg)

	sub := subscription.NewSubscription("sub-a", "sub-a", "https://example.com/a", false, false)
	subMgr.Register(sub)
	addExportTestNode(t, pool, sub, `{"type":"vless","tag":"vless","server":"1.1.1.1","server_port":443}`, true)

	exporter := NewExporter(Config{Pool: pool, RuntimeCfg: cfgPtr})
	snapshot := exporter.Refresh(context.Background())
	if snapshot.LastError != "" {
		t.Fatalf("Refresh LastError = %q", snapshot.LastError)
	}
	if snapshot.NodeCount != 0 {
		t.Fatalf("NodeCount = %d, want 0", snapshot.NodeCount)
	}
}

func TestExporterValidateToken(t *testing.T) {
	cfgPtr := &atomic.Pointer[config.RuntimeConfig]{}
	cfg := config.NewDefaultRuntimeConfig()
	cfg.HealthyNodeSubscriptionEnabled = true
	cfg.HealthyNodeSubscriptionToken = "export-token"
	cfgPtr.Store(cfg)

	exporter := NewExporter(Config{RuntimeCfg: cfgPtr})
	if !exporter.ValidateToken("export-token") {
		t.Fatal("expected configured token to validate")
	}
	if exporter.ValidateToken("wrong-token") {
		t.Fatal("expected wrong token to be rejected")
	}

	cfg.HealthyNodeSubscriptionEnabled = false
	cfgPtr.Store(cfg)
	if exporter.ValidateToken("export-token") {
		t.Fatal("expected disabled exporter to reject token")
	}
}
