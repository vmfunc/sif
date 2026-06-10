/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2026 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package sif

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dropalldatabases/sif/internal/config"
	"github.com/dropalldatabases/sif/internal/finding"
)

// notifyWebhookBody is the generic-webhook wire shape, mirrored here so the
// wiring test can assert which findings crossed the severity floor without
// reaching into the notify package internals.
type notifyWebhookBody struct {
	Count    int `json:"count"`
	Findings []struct {
		Severity string `json:"severity"`
		Key      string `json:"key"`
	} `json:"findings"`
}

// mixedSeverityFindings spans the whole ladder so a floor test has something to
// drop on either side of every threshold.
func mixedSeverityFindings() []finding.Finding {
	return []finding.Finding{
		{Target: "https://t.test", Module: "headers", Severity: finding.SeverityInfo, Key: "headers:s", Title: "server"},
		{Target: "https://t.test", Module: "redirect", Severity: finding.SeverityLow, Key: "redirect:r", Title: "open redirect"},
		{Target: "https://t.test", Module: "sql", Severity: finding.SeverityMedium, Key: "sql:e", Title: "db error"},
		{Target: "https://t.test", Module: "cors", Severity: finding.SeverityHigh, Key: "cors:c", Title: "reflected origin"},
		{Target: "https://t.test", Module: "lfi", Severity: finding.SeverityCritical, Key: "lfi:l", Title: "path traversal"},
	}
}

func TestNotifyFindingsSeverityFilter(t *testing.T) {
	tests := []struct {
		name     string
		floor    string
		wantKeys []string
	}{
		{name: "medium drops info+low", floor: "medium", wantKeys: []string{"sql:e", "cors:c", "lfi:l"}},
		{name: "high drops everything below", floor: "high", wantKeys: []string{"cors:c", "lfi:l"}},
		{name: "info keeps all", floor: "info", wantKeys: []string{"headers:s", "redirect:r", "sql:e", "cors:c", "lfi:l"}},
		{name: "critical keeps only critical", floor: "critical", wantKeys: []string{"lfi:l"}},
		// an unrecognized floor must default to medium, not let info through.
		{name: "garbage floor defaults medium", floor: "bogus", wantKeys: []string{"sql:e", "cors:c", "lfi:l"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got notifyWebhookBody
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(body, &got); err != nil {
					t.Errorf("unmarshal webhook body: %v", err)
				}
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(srv.Close)

			// route notify at the test server via the generic webhook env var.
			t.Setenv("SLACK_WEBHOOK_URL", "")
			t.Setenv("DISCORD_WEBHOOK_URL", "")
			t.Setenv("TELEGRAM_BOT_TOKEN", "")
			t.Setenv("TELEGRAM_CHAT_ID", "")
			t.Setenv("NOTIFY_WEBHOOK_URL", srv.URL)

			app := &App{settings: &config.Settings{
				Notify:         true,
				NotifySeverity: tt.floor,
				Timeout:        time.Second,
			}}
			if err := app.notifyFindings(context.Background(), mixedSeverityFindings()); err != nil {
				t.Fatalf("notifyFindings: %v", err)
			}

			gotKeys := make([]string, 0, len(got.Findings))
			for _, f := range got.Findings {
				gotKeys = append(gotKeys, f.Key)
			}
			if !equalStringSets(gotKeys, tt.wantKeys) {
				t.Errorf("floor %q delivered keys %v, want %v", tt.floor, gotKeys, tt.wantKeys)
			}
			if got.Count != len(tt.wantKeys) {
				t.Errorf("floor %q count = %d, want %d", tt.floor, got.Count, len(tt.wantKeys))
			}
		})
	}
}

func TestNotifyFindingsBelowFloorIsNoop(t *testing.T) {
	// every finding below the floor -> nothing crosses -> no POST at all.
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	t.Setenv("SLACK_WEBHOOK_URL", "")
	t.Setenv("DISCORD_WEBHOOK_URL", "")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")
	t.Setenv("NOTIFY_WEBHOOK_URL", srv.URL)

	app := &App{settings: &config.Settings{
		Notify:         true,
		NotifySeverity: "critical",
		Timeout:        time.Second,
	}}
	infoOnly := []finding.Finding{
		{Target: "https://t.test", Module: "headers", Severity: finding.SeverityInfo, Key: "headers:s", Title: "server"},
	}
	if err := app.notifyFindings(context.Background(), infoOnly); err != nil {
		t.Fatalf("notifyFindings: %v", err)
	}
	if hit {
		t.Fatal("notifyFindings posted with everything below floor, want no-op")
	}
}

// equalStringSets reports whether a and b contain the same elements regardless
// of order; the wire order mirrors input order, but order isn't the contract.
func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
