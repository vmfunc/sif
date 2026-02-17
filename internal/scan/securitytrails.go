/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/output"
)

const securityTrailsBaseURL = "https://api.securitytrails.com/v1"

// SecurityTrailsResult holds discovered domains from SecurityTrails API
type SecurityTrailsResult struct {
	Domain            string   `json:"domain"`
	Subdomains        []string `json:"subdomains,omitempty"`
	AssociatedDomains []string `json:"associated_domains,omitempty"`
}

// stSubdomainsResponse is the raw response from the subdomains endpoint -
// returns prefix labels, not FQDNs
type stSubdomainsResponse struct {
	Subdomains []string `json:"subdomains"`
}

type stAssociatedResponse struct {
	Records []stAssociatedRecord `json:"records"`
}

type stAssociatedRecord struct {
	Hostname string `json:"hostname"`
}

// SecurityTrails queries the SecurityTrails API for subdomains and associated domains.
// API key should be provided via the SECURITYTRAILS_API_KEY environment variable.
func SecurityTrails(targetURL string, timeout time.Duration, logdir string) (*SecurityTrailsResult, error) {
	output.ScanStart("SecurityTrails lookup")

	spin := output.NewSpinner("querying SecurityTrails API")
	spin.Start()

	apiKey := os.Getenv("SECURITYTRAILS_API_KEY")
	if apiKey == "" {
		spin.Stop()
		output.Warn("SECURITYTRAILS_API_KEY environment variable not set, skipping SecurityTrails lookup")
		return nil, fmt.Errorf("SECURITYTRAILS_API_KEY environment variable not set")
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		spin.Stop()
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}
	hostname := parsedURL.Hostname()

	client := &http.Client{Timeout: timeout}

	result := &SecurityTrailsResult{
		Domain: hostname,
	}

	// fetch subdomains
	spin.Update("fetching subdomains for " + hostname)
	subs, err := querySTSubdomains(client, hostname, apiKey)
	if err != nil {
		// non-fatal - still try associated domains
		output.Warn("SecurityTrails subdomains failed: %v", err)
	} else {
		result.Subdomains = subs
	}

	// fetch associated domains
	spin.Update("fetching associated domains for " + hostname)
	assoc, err := querySTAssociated(client, hostname, apiKey)
	if err != nil {
		output.Warn("SecurityTrails associated domains failed: %v", err)
	} else {
		result.AssociatedDomains = assoc
	}

	spin.Stop()

	if logdir != "" {
		sanitizedURL := strings.Split(targetURL, "://")[1]
		if err := logger.WriteHeader(sanitizedURL, logdir, "SecurityTrails lookup"); err != nil {
			output.Error("error writing log header: %v", err)
		}
		logSecurityTrailsResults(sanitizedURL, logdir, result)
	}

	printSecurityTrailsResults(result)

	total := len(result.Subdomains) + len(result.AssociatedDomains)
	output.ScanComplete("SecurityTrails lookup", total, "domains discovered")

	return result, nil
}

// DiscoveredURLs returns all discovered domains as https:// URLs.
// used by the orchestration layer for target expansion.
func (r *SecurityTrailsResult) DiscoveredURLs() []string {
	seen := make(map[string]struct{})
	var urls []string

	for _, sub := range r.Subdomains {
		fqdn := sub + "." + r.Domain
		if _, ok := seen[fqdn]; !ok {
			seen[fqdn] = struct{}{}
			urls = append(urls, "https://"+fqdn)
		}
	}

	for _, assoc := range r.AssociatedDomains {
		if _, ok := seen[assoc]; !ok {
			seen[assoc] = struct{}{}
			urls = append(urls, "https://"+assoc)
		}
	}

	return urls
}

func querySTSubdomains(client *http.Client, hostname, apiKey string) ([]string, error) {
	reqURL := fmt.Sprintf("%s/domain/%s/subdomains", securityTrailsBaseURL, hostname)
	body, err := doSTRequest(client, reqURL, apiKey)
	if err != nil {
		return nil, err
	}

	var resp stSubdomainsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse subdomains response: %w", err)
	}

	return resp.Subdomains, nil
}

func querySTAssociated(client *http.Client, hostname, apiKey string) ([]string, error) {
	reqURL := fmt.Sprintf("%s/domain/%s/associated", securityTrailsBaseURL, hostname)
	body, err := doSTRequest(client, reqURL, apiKey)
	if err != nil {
		return nil, err
	}

	var resp stAssociatedResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse associated response: %w", err)
	}

	domains := make([]string, 0, len(resp.Records))
	for _, rec := range resp.Records {
		if rec.Hostname != "" {
			domains = append(domains, rec.Hostname)
		}
	}

	return domains, nil
}

// doSTRequest makes an authenticated GET to the SecurityTrails API
func doSTRequest(client *http.Client, reqURL, apiKey string) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("APIKEY", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("SecurityTrails request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid SecurityTrails API key (status %d)", resp.StatusCode)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("SecurityTrails rate limit exceeded")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("SecurityTrails API error (status %d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return body, nil
}

func printSecurityTrailsResults(result *SecurityTrailsResult) {
	output.Info("Domain: %s", output.Highlight.Render(result.Domain))

	if len(result.Subdomains) > 0 {
		output.Info("Subdomains found: %d", len(result.Subdomains))
		for _, sub := range result.Subdomains {
			output.Success("  %s.%s", sub, result.Domain)
		}
	}

	if len(result.AssociatedDomains) > 0 {
		output.Info("Associated domains found: %d", len(result.AssociatedDomains))
		for _, assoc := range result.AssociatedDomains {
			output.Success("  %s", assoc)
		}
	}
}

func logSecurityTrailsResults(sanitizedURL, logdir string, result *SecurityTrailsResult) {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Domain: %s\n", result.Domain))

	if len(result.Subdomains) > 0 {
		sb.WriteString(fmt.Sprintf("\nSubdomains (%d):\n", len(result.Subdomains)))
		for _, sub := range result.Subdomains {
			sb.WriteString(fmt.Sprintf("  %s.%s\n", sub, result.Domain))
		}
	}

	if len(result.AssociatedDomains) > 0 {
		sb.WriteString(fmt.Sprintf("\nAssociated Domains (%d):\n", len(result.AssociatedDomains)))
		for _, assoc := range result.AssociatedDomains {
			sb.WriteString(fmt.Sprintf("  %s\n", assoc))
		}
	}

	logger.Write(sanitizedURL, logdir, sb.String())
}
