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

package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dropalldatabases/sif/internal/finding"
)

// sampleFindings returns a small mixed-severity batch for payload assertions.
func sampleFindings() []finding.Finding {
	return []finding.Finding{
		{Target: "https://a.test", Module: "cors", Severity: finding.SeverityHigh, Key: "cors:a", Title: "reflected origin", Raw: "ACAO echo"},
		{Target: "https://a.test", Module: "headers", Severity: finding.SeverityInfo, Key: "headers:x", Title: "Server header", Raw: "nginx"},
	}
}

// capture records the method, content-type and raw body of the request a provider
// makes, so each test can assert the wire shape without a real network.
type capture struct {
	method      string
	contentType string
	path        string
	body        []byte
}

// captureServer stands up an httptest server that records the single inbound
// request into c and replies 200, the happy path every provider expects.
func captureServer(t *testing.T, c *capture) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.method = r.Method
		c.contentType = r.Header.Get("Content-Type")
		c.path = r.URL.Path
		c.body = body
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSlackPayloadShape(t *testing.T) {
	var c capture
	srv := captureServer(t, &c)

	p := &slackProvider{webhook: srv.URL}
	if err := p.send(context.Background(), srv.Client(), sampleFindings()); err != nil {
		t.Fatalf("slack send: %v", err)
	}

	assertPostJSON(t, c)
	var payload slackPayload
	if err := json.Unmarshal(c.body, &payload); err != nil {
		t.Fatalf("unmarshal slack body: %v", err)
	}
	// slack keys on "text"; both findings must appear, code-block fenced.
	if !strings.Contains(payload.Text, "reflected origin") || !strings.Contains(payload.Text, "Server header") {
		t.Errorf("slack text missing findings: %q", payload.Text)
	}
	if !strings.HasPrefix(payload.Text, "```") {
		t.Errorf("slack text not code-block fenced: %q", payload.Text)
	}
}

func TestDiscordPayloadShape(t *testing.T) {
	var c capture
	srv := captureServer(t, &c)

	p := &discordProvider{webhook: srv.URL}
	if err := p.send(context.Background(), srv.Client(), sampleFindings()); err != nil {
		t.Fatalf("discord send: %v", err)
	}

	assertPostJSON(t, c)
	var payload discordPayload
	if err := json.Unmarshal(c.body, &payload); err != nil {
		t.Fatalf("unmarshal discord body: %v", err)
	}
	// discord keys on "content", not "text".
	if !strings.Contains(payload.Content, "reflected origin") {
		t.Errorf("discord content missing finding: %q", payload.Content)
	}
}

func TestTelegramPayloadShape(t *testing.T) {
	var c capture
	srv := captureServer(t, &c)

	// repoint the bot api base at the test server for the lifetime of this test.
	orig := telegramAPIBase
	telegramAPIBase = srv.URL
	t.Cleanup(func() { telegramAPIBase = orig })

	p := &telegramProvider{token: "555:tok", chatID: "42"}
	if err := p.send(context.Background(), srv.Client(), sampleFindings()); err != nil {
		t.Fatalf("telegram send: %v", err)
	}

	assertPostJSON(t, c)
	// the token rides the path and the method is sendMessage.
	if c.path != "/bot555:tok/sendMessage" {
		t.Errorf("telegram path = %q, want /bot555:tok/sendMessage", c.path)
	}
	var payload telegramPayload
	if err := json.Unmarshal(c.body, &payload); err != nil {
		t.Fatalf("unmarshal telegram body: %v", err)
	}
	if payload.ChatID != "42" {
		t.Errorf("telegram chat_id = %q, want 42", payload.ChatID)
	}
	if !strings.Contains(payload.Text, "reflected origin") {
		t.Errorf("telegram text missing finding: %q", payload.Text)
	}
}

func TestWebhookPayloadShape(t *testing.T) {
	var c capture
	srv := captureServer(t, &c)

	p := &webhookProvider{url: srv.URL}
	if err := p.send(context.Background(), srv.Client(), sampleFindings()); err != nil {
		t.Fatalf("webhook send: %v", err)
	}

	assertPostJSON(t, c)
	var payload webhookPayload
	if err := json.Unmarshal(c.body, &payload); err != nil {
		t.Fatalf("unmarshal webhook body: %v", err)
	}
	// generic webhook carries structured findings, not a prerendered blob.
	if payload.Count != 2 || len(payload.Findings) != 2 {
		t.Fatalf("webhook count = %d / %d findings, want 2", payload.Count, len(payload.Findings))
	}
	first := payload.Findings[0]
	if first.Severity != "high" {
		t.Errorf("webhook severity = %q, want canonical string \"high\"", first.Severity)
	}
	if first.Key != "cors:a" || first.Module != "cors" {
		t.Errorf("webhook finding fields wrong: %+v", first)
	}
}

func TestProviderNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)

	p := &slackProvider{webhook: srv.URL}
	if err := p.send(context.Background(), srv.Client(), sampleFindings()); err == nil {
		t.Fatal("send to 403 endpoint: want error, got nil")
	}
}

func TestSendNoProviderIsNoop(t *testing.T) {
	clearNotifyEnv(t)
	// no env, no config file -> zero providers -> Send must not error.
	if err := Send(context.Background(), sampleFindings(), Options{Timeout: time.Second}); err != nil {
		t.Fatalf("Send with no provider: want nil, got %v", err)
	}
}

func TestSendEmptyFindingsIsNoop(t *testing.T) {
	// even with a provider configured, an empty batch must not POST anything.
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	clearNotifyEnv(t)
	t.Setenv(envSlackWebhook, srv.URL)
	if err := Send(context.Background(), nil, Options{Timeout: time.Second}); err != nil {
		t.Fatalf("Send with empty findings: want nil, got %v", err)
	}
	if hit {
		t.Fatal("Send with empty findings posted to provider, want no-op")
	}
}

func TestSendDeliversToConfiguredProvider(t *testing.T) {
	var c capture
	srv := captureServer(t, &c)

	clearNotifyEnv(t)
	t.Setenv(envSlackWebhook, srv.URL)
	if err := Send(context.Background(), sampleFindings(), Options{Timeout: time.Second}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if c.method != http.MethodPost {
		t.Fatalf("provider not hit (method=%q)", c.method)
	}
}

// assertPostJSON checks the request was a json POST.
func assertPostJSON(t *testing.T, c capture) {
	t.Helper()
	if c.method != http.MethodPost {
		t.Errorf("method = %q, want POST", c.method)
	}
	if c.contentType != contentTypeJSON {
		t.Errorf("content-type = %q, want %q", c.contentType, contentTypeJSON)
	}
}
