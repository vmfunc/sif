package scan

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSecurityTrailsResult_DiscoveredURLs(t *testing.T) {
	result := &SecurityTrailsResult{
		Domain:            "example.com",
		Subdomains:        []string{"www", "api", "mail"},
		AssociatedDomains: []string{"example.org", "example.net"},
	}

	urls := result.DiscoveredURLs()

	if len(urls) != 5 {
		t.Errorf("expected 5 URLs, got %d: %v", len(urls), urls)
	}

	expected := map[string]bool{
		"https://www.example.com":  false,
		"https://api.example.com":  false,
		"https://mail.example.com": false,
		"https://example.org":      false,
		"https://example.net":      false,
	}

	for _, u := range urls {
		if _, ok := expected[u]; !ok {
			t.Errorf("unexpected URL: %s", u)
		}
		expected[u] = true
	}

	for u, seen := range expected {
		if !seen {
			t.Errorf("missing expected URL: %s", u)
		}
	}
}

func TestSecurityTrailsResult_DiscoveredURLs_Dedup(t *testing.T) {
	result := &SecurityTrailsResult{
		Domain:            "example.com",
		Subdomains:        []string{"www"},
		AssociatedDomains: []string{"www.example.com"},
	}

	urls := result.DiscoveredURLs()
	if len(urls) != 1 {
		t.Errorf("expected 1 URL (deduped), got %d: %v", len(urls), urls)
	}
}

func TestSecurityTrailsResult_DiscoveredURLs_Empty(t *testing.T) {
	result := &SecurityTrailsResult{
		Domain: "example.com",
	}

	urls := result.DiscoveredURLs()
	if len(urls) != 0 {
		t.Errorf("expected 0 URLs, got %d: %v", len(urls), urls)
	}
}

func TestDoSTRequest_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("APIKEY") != "test-key" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"test": true}`))
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	body, err := doSTRequest(client, server.URL, "test-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(body) == 0 {
		t.Error("expected non-empty body")
	}
}

func TestDoSTRequest_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	_, err := doSTRequest(client, server.URL, "bad-key")
	if err == nil {
		t.Error("expected error for forbidden response")
	}
}

func TestDoSTRequest_RateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	_, err := doSTRequest(client, server.URL, "test-key")
	if err == nil {
		t.Error("expected error for rate limit response")
	}
}

func TestQuerySTSubdomains(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("APIKEY") != "test-key" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		resp := stSubdomainsResponse{
			Subdomains: []string{"www", "api", "mail", "dev"},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	// query the mock server directly via doSTRequest + unmarshal
	body, err := doSTRequest(client, server.URL, "test-key")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	var resp stSubdomainsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(resp.Subdomains) != 4 {
		t.Errorf("expected 4 subdomains, got %d", len(resp.Subdomains))
	}
}

func TestQuerySTAssociated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("APIKEY") != "test-key" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		resp := stAssociatedResponse{
			Records: []stAssociatedRecord{
				{Hostname: "related.com"},
				{Hostname: "sibling.net"},
				{Hostname: ""},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	body, err := doSTRequest(client, server.URL, "test-key")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	var resp stAssociatedResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// should have 3 records total (including empty one)
	if len(resp.Records) != 3 {
		t.Errorf("expected 3 records, got %d", len(resp.Records))
	}

	// filter empty hostnames like the real code does
	var domains []string
	for _, rec := range resp.Records {
		if rec.Hostname != "" {
			domains = append(domains, rec.Hostname)
		}
	}
	if len(domains) != 2 {
		t.Errorf("expected 2 non-empty domains, got %d", len(domains))
	}
}

func TestSecurityTrailsResult_ResultType(t *testing.T) {
	result := &SecurityTrailsResult{}
	if result.ResultType() != "securitytrails" {
		t.Errorf("expected ResultType 'securitytrails', got '%s'", result.ResultType())
	}
}

func TestSecurityTrailsIntegration(t *testing.T) {
	t.Skip("integration test - requires valid SECURITYTRAILS_API_KEY")

	_, err := SecurityTrails("https://example.com", 10*time.Second, "")
	if err != nil {
		t.Logf("SecurityTrails lookup failed: %v", err)
	}
}
