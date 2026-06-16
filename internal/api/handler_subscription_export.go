package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/Resinat/Resin/internal/service"
	"github.com/Resinat/Resin/internal/subscriptionexport"
)

type healthyNodeSubscriptionStatusResponse struct {
	Enabled          bool              `json:"enabled"`
	ContentType      string            `json:"content_type"`
	NodeCount        int               `json:"node_count"`
	ClashNodeCount   int               `json:"clash_node_count"`
	GeneratedAt      string            `json:"generated_at,omitempty"`
	LastError        string            `json:"last_error,omitempty"`
	RefreshInterval  string            `json:"refresh_interval"`
	SubscriptionURL  string            `json:"subscription_url,omitempty"`
	SubscriptionURLs map[string]string `json:"subscription_urls,omitempty"`
	TokenRequired    bool              `json:"token_required"`
}

func HandleGetHealthyNodeSubscriptionStatus(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cp == nil || cp.SubExporter == nil {
			WriteJSON(w, http.StatusOK, healthyNodeSubscriptionStatusResponse{
				ContentType:     subscriptionexport.ContentTypeSingbox,
				RefreshInterval: "0s",
				TokenRequired:   true,
			})
			return
		}
		WriteJSON(w, http.StatusOK, healthyNodeSubscriptionStatus(cp.SubExporter.Snapshot(), r))
	}
}

func HandleRefreshHealthyNodeSubscription(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cp == nil || cp.SubExporter == nil {
			WriteError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "healthy node subscription exporter is not available")
			return
		}
		snapshot := cp.SubExporter.Refresh(r.Context())
		WriteJSON(w, http.StatusOK, healthyNodeSubscriptionStatus(snapshot, r))
	}
}

func HandleDownloadHealthyNodeSubscription(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cp == nil || cp.SubExporter == nil {
			WriteError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "healthy node subscription exporter is not available")
			return
		}
		token := r.URL.Query().Get("token")
		if !cp.SubExporter.ValidateToken(token) {
			WriteError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid subscription token")
			return
		}
		format, ok := subscriptionexport.ParseFormat(r.URL.Query().Get("format"))
		if !ok {
			WriteError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "unsupported subscription format")
			return
		}
		snapshot, content := cp.SubExporter.Content(r.Context(), format)
		if !snapshot.Enabled {
			WriteError(w, http.StatusNotFound, "NOT_FOUND", "healthy node subscription export is disabled")
			return
		}
		if snapshot.LastError != "" {
			WriteError(w, http.StatusServiceUnavailable, "UNAVAILABLE", snapshot.LastError)
			return
		}
		w.Header().Set("Content-Type", format.ContentType())
		w.Header().Set("Cache-Control", "no-store")
		if !snapshot.GeneratedAt.IsZero() {
			w.Header().Set("Last-Modified", snapshot.GeneratedAt.Format(http.TimeFormat))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}
}

func healthyNodeSubscriptionStatus(
	snapshot subscriptionexport.Snapshot,
	r *http.Request,
) healthyNodeSubscriptionStatusResponse {
	resp := healthyNodeSubscriptionStatusResponse{
		Enabled:         snapshot.Enabled,
		ContentType:     snapshot.ContentType,
		NodeCount:       snapshot.NodeCount,
		ClashNodeCount:  snapshot.ClashNodeCount,
		LastError:       snapshot.LastError,
		RefreshInterval: snapshot.RefreshInterval,
		TokenRequired:   true,
	}
	if !snapshot.GeneratedAt.IsZero() {
		resp.GeneratedAt = snapshot.GeneratedAt.UTC().Format(time.RFC3339Nano)
	}
	if r != nil {
		resp.SubscriptionURL = publicHealthyNodeSubscriptionURL(r, subscriptionexport.FormatSingbox)
		resp.SubscriptionURLs = map[string]string{
			subscriptionexport.FormatSingbox.String(): resp.SubscriptionURL,
			subscriptionexport.FormatClash.String():   publicHealthyNodeSubscriptionURL(r, subscriptionexport.FormatClash),
		}
	}
	return resp
}

func publicHealthyNodeSubscriptionURL(r *http.Request, format subscriptionexport.Format) string {
	if r == nil || r.URL == nil {
		return subscriptionexport.SubscriptionPath
	}
	u := *r.URL
	u.Path = subscriptionexport.SubscriptionPath
	u.RawPath = ""
	query := u.Query()
	query.Set("token", "<token>")
	if format != subscriptionexport.FormatSingbox {
		query.Set("format", format.String())
	} else {
		query.Del("format")
	}
	u.RawQuery = strings.ReplaceAll(query.Encode(), "%3Ctoken%3E", "<token>")
	u.Fragment = ""
	if u.Scheme == "" {
		u.Scheme = forwardedProto(r)
	}
	if u.Host == "" {
		u.Host = forwardedHost(r)
	}
	return u.String()
}

func forwardedProto(r *http.Request) string {
	if r == nil {
		return "http"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "http" || proto == "https" {
		return proto
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func forwardedHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	if host := r.Header.Get("X-Forwarded-Host"); host != "" {
		return host
	}
	return r.Host
}
