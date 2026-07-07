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

	"github.com/vmfunc/sif/internal/finding"
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

// deadURL returns a URL that will refuse connection: bind a listener, close
// it, reuse the address. good enough to force a transport-level error out of
// client.Do without touching the network.
func deadURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	u := srv.URL
	srv.Close()
	return u
}

// see redactTransportErr's doc comment (message.go) for why this matters.
func TestNotifyErrorRedactsSecretWebhookURL(t *testing.T) {
	host := deadURL(t)
	secret := host + "/services/T00000000/B11111111/SUPERSECRETTOKEN"
	p := &slackProvider{webhook: secret}
	err := p.send(context.Background(), http.DefaultClient, sampleFindings())
	if err == nil {
		t.Fatal("expected transport error")
	}
	if strings.Contains(err.Error(), "SUPERSECRETTOKEN") {
		t.Fatalf("LEAK: secret webhook token present in error: %v", err)
	}
	if !strings.Contains(err.Error(), strings.TrimPrefix(host, "http://")) {
		t.Errorf("error dropped the host too, operator can't debug: %v", err)
	}
}

func TestNotifyErrorRedactsTelegramToken(t *testing.T) {
	orig := telegramAPIBase
	host := deadURL(t)
	telegramAPIBase = host
	t.Cleanup(func() { telegramAPIBase = orig })

	p := &telegramProvider{token: "123456:AAHsupersecretbottoken", chatID: "42"}
	err := p.send(context.Background(), http.DefaultClient, sampleFindings())
	if err == nil {
		t.Fatal("expected transport error")
	}
	if strings.Contains(err.Error(), "AAHsupersecretbottoken") {
		t.Fatalf("LEAK: telegram bot token present in error: %v", err)
	}
	if !strings.Contains(err.Error(), strings.TrimPrefix(host, "http://")) {
		t.Errorf("error dropped the host too, operator can't debug: %v", err)
	}
}

// attacker-controlled finding content (a scanned target's page title, a
// crawled url, a cms name) reaches the slack/discord code block verbatim. a
// title that embeds a closing fence used to break out of our wrapping block
// and inject live markdown (mentions, masked links) into the channel.
func TestNotifyCodeBlockBreakoutNeutralized(t *testing.T) {
	var c capture
	srv := captureServer(t, &c)

	evil := []finding.Finding{{
		Target:   "https://evil.test",
		Module:   "probe",
		Severity: finding.SeverityHigh,
		Key:      "probe:x",
		Title:    "```\n@everyone pwned <https://evil.test|click>\n```",
	}}
	p := &discordProvider{webhook: srv.URL}
	if err := p.send(context.Background(), srv.Client(), evil); err != nil {
		t.Fatalf("send: %v", err)
	}
	var payload discordPayload
	if err := json.Unmarshal(c.body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// a clean payload has exactly the 2 fences we added (open+close); any more
	// means attacker content broke out.
	if fences := strings.Count(payload.Content, "```"); fences > 2 {
		t.Fatalf("INJECTION: attacker content added %d extra code fences, breaking out: %q", fences-2, payload.Content)
	}
}

// slack resolves a bare "<...|...>" as a link/mention independent of code-block
// boundaries, so the fence fix alone isn't enough for slack: the control
// characters (&, <, >) must be entity-escaped too.
func TestSlackEscapesControlChars(t *testing.T) {
	var c capture
	srv := captureServer(t, &c)

	evil := []finding.Finding{{
		Target:   "https://evil.test",
		Module:   "probe",
		Severity: finding.SeverityHigh,
		Key:      "probe:x",
		Title:    "<https://evil.test|click> & <!everyone>",
	}}
	p := &slackProvider{webhook: srv.URL}
	if err := p.send(context.Background(), srv.Client(), evil); err != nil {
		t.Fatalf("send: %v", err)
	}
	var payload slackPayload
	if err := json.Unmarshal(c.body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if strings.Contains(payload.Text, "<https://evil.test|click>") {
		t.Fatalf("INJECTION: unescaped slack link syntax reached the payload: %q", payload.Text)
	}
	if !strings.Contains(payload.Text, "&lt;https://evil.test|click&gt;") || !strings.Contains(payload.Text, "&amp;") {
		t.Fatalf("expected slack control chars entity-escaped, got: %q", payload.Text)
	}
}

// robustness sanity: confirm a zero http.Client.Timeout would mean an
// unbounded client. not a bug in notify per se, but documents that ctx, not
// Timeout, is what bounds a hung endpoint here.
func TestNotifyZeroTimeoutIsUnbounded(t *testing.T) {
	blocked := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-blocked
	}))
	t.Cleanup(func() { close(blocked); srv.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	p := &slackProvider{webhook: srv.URL}
	done := make(chan error, 1)
	go func() { done <- p.send(ctx, srv.Client(), sampleFindings()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected ctx-cancel error from hung endpoint")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("send did not honor ctx cancellation on hung endpoint")
	}
}
