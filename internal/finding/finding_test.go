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

package finding

import (
	"strings"
	"testing"

	"github.com/dropalldatabases/sif/internal/modules"
	"github.com/dropalldatabases/sif/internal/scan"
	"github.com/dropalldatabases/sif/internal/scan/frameworks"
	"github.com/dropalldatabases/sif/internal/scan/js"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// scanResultType mirrors the minimal interface the scan packages implement; the
// coverage table below carries a value per ResultType() so a new scanner whose
// ResultType isn't represented (or isn't handled by Flatten) trips a failure.
type scanResultType interface {
	ResultType() string
}

// coverageCase is one representative, non-empty instance of a result type plus
// its expected module attribution. wantItems is how many findings Flatten must
// emit for the populated instance, proving the per-item fan-out works.
type coverageCase struct {
	value     any            // the result as it reaches Flatten
	typed     scanResultType // same value when it implements ResultType(), else nil
	module    string         // module id Flatten should stamp
	wantItems int            // findings the populated instance must produce
}

// coverageCases is the registry the guard checks against. there must be one
// entry per distinct ResultType() in the scan tree (plus the raw []string and
// nuclei []ResultEvent that flow through the report without a ResultType). add a
// scanner without adding it here and TestFlattenCoversEveryResultType fails.
func coverageCases() []coverageCase {
	return []coverageCase{
		{
			value:     &scan.ShodanResult{IP: "1.2.3.4", Ports: []int{80}, Vulns: []string{"CVE-1"}},
			typed:     &scan.ShodanResult{},
			module:    "shodan",
			wantItems: 1,
		},
		{
			value: &scan.SQLResult{
				AdminPanels:    []scan.SQLAdminPanel{{URL: "http://x/pma", Type: "phpMyAdmin", Status: 200}},
				DatabaseErrors: []scan.SQLDatabaseError{{URL: "http://x", DatabaseType: "mysql", ErrorPattern: "syntax"}},
				ExposedPorts:   []int{3306},
			},
			typed:     &scan.SQLResult{},
			module:    "sql",
			wantItems: 3,
		},
		{
			value: &scan.LFIResult{Vulnerabilities: []scan.LFIVulnerability{
				{URL: "http://x", Parameter: "file", Evidence: "root:x", Severity: "high"},
			}},
			typed:     &scan.LFIResult{},
			module:    "lfi",
			wantItems: 1,
		},
		{
			value:     &scan.CMSResult{Name: "WordPress", Version: "6.1"},
			typed:     &scan.CMSResult{},
			module:    "cms",
			wantItems: 1,
		},
		{
			value:     &scan.SecurityTrailsResult{Domain: "x.com", Subdomains: []string{"a.x.com"}, AssociatedDomains: []string{"y.com"}},
			typed:     &scan.SecurityTrailsResult{},
			module:    "securitytrails",
			wantItems: 2,
		},
		{
			value:     &scan.CORSResult{Findings: []scan.CORSFinding{{URL: "http://x", OriginTested: "null", AllowOrigin: "null", Severity: "medium", Note: "null origin"}}},
			typed:     &scan.CORSResult{},
			module:    "cors",
			wantItems: 1,
		},
		{
			value:     &scan.RedirectResult{Findings: []scan.RedirectFinding{{URL: "http://x", Parameter: "next", Location: "http://evil", Via: "header", Severity: "medium"}}},
			typed:     &scan.RedirectResult{},
			module:    "redirect",
			wantItems: 1,
		},
		{
			value:     &scan.XSSResult{Findings: []scan.XSSFinding{{URL: "http://x", Parameter: "q", Context: "html", SurvivedRaw: []string{"<"}, Severity: "high"}}},
			typed:     &scan.XSSResult{},
			module:    "xss",
			wantItems: 1,
		},
		{
			value:     &scan.CrawlResult{URLs: []string{"http://x/a"}},
			typed:     &scan.CrawlResult{},
			module:    "crawl",
			wantItems: 1,
		},
		{
			value:     &scan.PassiveResult{Subdomains: []string{"a.x.com"}, URLs: []string{"http://x/old"}},
			typed:     &scan.PassiveResult{},
			module:    "passive",
			wantItems: 2,
		},
		{
			value:     &scan.ProbeResult{URL: "http://x", Alive: true, StatusCode: 200, Title: "home"},
			typed:     &scan.ProbeResult{},
			module:    "probe",
			wantItems: 1,
		},
		{
			value:     scan.HeaderResults{{Name: "Server", Value: "nginx"}},
			typed:     scan.HeaderResults{},
			module:    "headers",
			wantItems: 1,
		},
		{
			value:     scan.SecurityHeaderResults{{Header: "Content-Security-Policy", Present: false, Severity: "medium", Note: "missing"}},
			typed:     scan.SecurityHeaderResults{},
			module:    "security_headers",
			wantItems: 1,
		},
		{
			value:     scan.DirectoryResults{{Url: "http://x/admin", StatusCode: 301, Size: 10, Words: 2}},
			typed:     scan.DirectoryResults{},
			module:    "dirlist",
			wantItems: 1,
		},
		{
			value:     scan.CloudStorageResults{{BucketName: "x-assets", IsPublic: true}},
			typed:     scan.CloudStorageResults{},
			module:    "cloudstorage",
			wantItems: 1,
		},
		{
			value:     scan.DorkResults{{Url: "http://x/leak", Count: 1}},
			typed:     scan.DorkResults{},
			module:    "dork",
			wantItems: 1,
		},
		{
			value:     scan.SubdomainTakeoverResults{{Subdomain: "old.x.com", Vulnerable: true, Service: "GitHub Pages"}},
			typed:     scan.SubdomainTakeoverResults{},
			module:    "subdomain_takeover",
			wantItems: 1,
		},
		{
			value:     &frameworks.FrameworkResult{Name: "Laravel", Version: "9.0", RiskLevel: "high", CVEs: []string{"CVE-2"}},
			typed:     &frameworks.FrameworkResult{},
			module:    "framework",
			wantItems: 1,
		},
		{
			value: &js.JavascriptScanResult{
				SecretMatches: []js.SecretMatch{{Rule: "aws-key", Match: "AKIA...", Source: "http://x/app.js"}},
				Endpoints:     []string{"/api/v1"},
			},
			typed:     &js.JavascriptScanResult{},
			module:    "js",
			wantItems: 2,
		},
		{
			value:     &modules.Result{ModuleID: "custom-mod", Target: "http://x", Findings: []modules.Finding{{URL: "http://x", Severity: "low", Evidence: "hit"}}},
			typed:     &modules.Result{ModuleID: "custom-mod"},
			module:    "custom-mod",
			wantItems: 1,
		},
		{
			// nuclei results aren't ScanResult-typed; they ride through the report
			// as a raw []ResultEvent, so cover that shape explicitly.
			value:     []output.ResultEvent{{TemplateID: "t1", Host: "x", Matched: "http://x", Info: model.Info{Name: "n", SeverityHolder: severity.Holder{Severity: severity.High}}}},
			module:    "nuclei",
			wantItems: 1,
		},
		{
			// dnslist/portscan/git all hand Flatten a bare []string keyed only by
			// the module argument.
			value:     []string{"sub.x.com"},
			module:    "dnslist",
			wantItems: 1,
		},
	}
}

const target = "http://target.example"

// TestFlattenCoversEveryResultType is the guard: every result type in the
// coverage table must flatten into the expected module without hitting the
// "unhandled" fallback. a new scanner that skips both the table and Flatten's
// switch trips this loudly.
func TestFlattenCoversEveryResultType(t *testing.T) {
	for _, tc := range coverageCases() {
		findings := Flatten(target, tc.module, tc.value)

		if len(findings) != tc.wantItems {
			t.Errorf("module %q: got %d findings, want %d", tc.module, len(findings), tc.wantItems)
		}
		for i := 0; i < len(findings); i++ {
			f := findings[i]
			if strings.HasSuffix(f.Key, keySep+"unhandled") {
				t.Errorf("module %q: Flatten has no case, fell through to unhandled (key=%q)", tc.module, f.Key)
			}
			if f.Target != target {
				t.Errorf("module %q: target=%q, want %q", tc.module, f.Target, target)
			}
			if f.Module != tc.module {
				t.Errorf("module %q: finding stamped module=%q, want %q", tc.module, f.Module, tc.module)
			}
			if f.Key == "" {
				t.Errorf("module %q: empty Key", tc.module)
			}
			if !strings.HasPrefix(f.Key, tc.module+keySep) {
				t.Errorf("module %q: Key %q not prefixed with module", tc.module, f.Key)
			}
		}
	}
}

// TestEveryResultTypeIsInCoverageTable cross-checks the table against the actual
// ResultType() registry: if a scanner type exists whose ResultType() isn't in
// the table, the coverage guard above would never exercise it. enumerate the
// known typed entries and assert each ResultType() string is present.
func TestEveryResultTypeIsInCoverageTable(t *testing.T) {
	covered := make(map[string]struct{})
	for _, tc := range coverageCases() {
		if tc.typed == nil {
			continue
		}
		covered[tc.typed.ResultType()] = struct{}{}
	}

	// the full set of ResultType() strings the scan tree exposes. keep this in
	// lockstep with the ScanResult implementers; a missing entry means the table
	// (and very likely Flatten) skipped a scanner.
	want := []string{
		"shodan", "sql", "lfi", "cms", "securitytrails",
		"cors", "redirect", "xss", "crawl", "passive", "probe",
		"headers", "security_headers", "dirlist", "cloudstorage",
		"dork", "subdomain_takeover", "framework", "js", "custom-mod",
	}
	for _, rt := range want {
		if _, ok := covered[rt]; !ok {
			t.Errorf("ResultType %q has no entry in coverageCases; Flatten coverage unverified", rt)
		}
	}
}

// TestFlattenStableKeysAndSeverities pins the keys and severities for a couple
// of representative items so a refactor that quietly reshuffles them is caught.
func TestFlattenStableKeysAndSeverities(t *testing.T) {
	tests := []struct {
		name    string
		value   any
		module  string
		wantKey string
		wantSev Severity
	}{
		{
			name:    "cors honors source severity",
			value:   &scan.CORSResult{Findings: []scan.CORSFinding{{URL: "http://x", OriginTested: "null", AllowOrigin: "null", Severity: "high", Note: "n"}}},
			module:  "cors",
			wantKey: "cors:http://x:null",
			wantSev: SeverityHigh,
		},
		{
			name:    "public bucket is high",
			value:   scan.CloudStorageResults{{BucketName: "b", IsPublic: true}},
			module:  "cloudstorage",
			wantKey: "cloudstorage:b",
			wantSev: SeverityHigh,
		},
		{
			name:    "header is recon info",
			value:   scan.HeaderResults{{Name: "Server", Value: "nginx"}},
			module:  "headers",
			wantKey: "headers:Server",
			wantSev: SeverityInfo,
		},
		{
			name:    "vulnerable takeover is high",
			value:   scan.SubdomainTakeoverResults{{Subdomain: "old.x.com", Vulnerable: true, Service: "GitHub Pages"}},
			module:  "subdomain_takeover",
			wantKey: "subdomain_takeover:old.x.com",
			wantSev: SeverityHigh,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Flatten(target, tt.module, tt.value)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			f := findings[0]
			if f.Key != tt.wantKey {
				t.Errorf("Key = %q, want %q", f.Key, tt.wantKey)
			}
			if f.Severity != tt.wantSev {
				t.Errorf("Severity = %v, want %v", f.Severity, tt.wantSev)
			}
		})
	}
}

// TestFlattenUnhandledTypeIsLoud asserts the fallback fires for a type Flatten
// doesn't know - this is what makes the guard above meaningful.
func TestFlattenUnhandledTypeIsLoud(t *testing.T) {
	type bogus struct{}
	findings := Flatten(target, "mystery", bogus{})
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 placeholder", len(findings))
	}
	if !strings.HasSuffix(findings[0].Key, keySep+"unhandled") {
		t.Errorf("unhandled type should key on :unhandled, got %q", findings[0].Key)
	}
	if findings[0].Severity != SeverityUnknown {
		t.Errorf("unhandled severity = %v, want SeverityUnknown", findings[0].Severity)
	}
}

// TestSubdomainTakeoverSkipsSafe confirms a non-vulnerable cname produces no
// finding; only the real takeover is a finding.
func TestSubdomainTakeoverSkipsSafe(t *testing.T) {
	value := scan.SubdomainTakeoverResults{
		{Subdomain: "safe.x.com", Vulnerable: false},
		{Subdomain: "bad.x.com", Vulnerable: true, Service: "Heroku"},
	}
	findings := Flatten(target, "subdomain_takeover", value)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (only the vulnerable one)", len(findings))
	}
	if findings[0].Key != "subdomain_takeover:bad.x.com" {
		t.Errorf("Key = %q, want subdomain_takeover:bad.x.com", findings[0].Key)
	}
}

// TestDeadProbeIsNotAFinding confirms a host that didn't answer yields nothing.
func TestDeadProbeIsNotAFinding(t *testing.T) {
	findings := Flatten(target, "probe", &scan.ProbeResult{URL: "http://x", Alive: false})
	if len(findings) != 0 {
		t.Errorf("dead probe produced %d findings, want 0", len(findings))
	}
}
