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

package js

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/antchfx/htmlquery"
	charmlog "github.com/charmbracelet/log"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/output"
	"github.com/vmfunc/sif/internal/scan/js/frameworks"
)

type JavascriptScanResult struct {
	SupabaseResults      []supabaseScanResult `json:"supabase_results"`
	FoundEnvironmentVars map[string]string    `json:"environment_variables"`
	SecretMatches        []SecretMatch        `json:"secret_matches"`
	Endpoints            []string             `json:"endpoints"`
}

// ResultType implements the ScanResult interface.
func (r *JavascriptScanResult) ResultType() string { return "js" }

// SupabaseFinding is the exported view of one discovered supabase project. the
// raw supabaseScanResult stays package-private (it carries scan internals), so
// downstream normalizers consume this projection instead.
type SupabaseFinding struct {
	ProjectId   string
	Role        string
	Collections int
}

// SupabaseFindings projects the package-private supabase results into a stable
// exported shape for the finding normalizer; role is what makes one interesting
// (a non-anon key is the real bug).
func (r *JavascriptScanResult) SupabaseFindings() []SupabaseFinding {
	out := make([]SupabaseFinding, 0, len(r.SupabaseResults))
	for i := 0; i < len(r.SupabaseResults); i++ {
		s := r.SupabaseResults[i]
		out = append(out, SupabaseFinding{
			ProjectId:   s.ProjectId,
			Role:        s.Role,
			Collections: len(s.Collections),
		})
	}
	return out
}

// maxHTMLBodySize caps how much of a page we read for script extraction so a
// huge or hostile response cannot exhaust memory.
const maxHTMLBodySize = 5 * 1024 * 1024

func JavascriptScan(url string, timeout time.Duration, threads int, logdir string) (*JavascriptScanResult, error) {
	log := output.Module("JS")
	log.Start()

	spin := output.NewSpinner("Scanning JavaScript files")
	spin.Start()

	client := httpx.Client(timeout)

	baseUrl, err := urlutil.Parse(url)
	if err != nil {
		spin.Stop()
		return nil, err
	}
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, url, http.NoBody)
	if err != nil {
		spin.Stop()
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		spin.Stop()
		return nil, err
	}
	defer resp.Body.Close()

	doc, err := htmlquery.Parse(io.LimitReader(resp.Body, maxHTMLBodySize))
	if err != nil {
		return nil, err
	}

	var scripts []string
	nodes, err := htmlquery.QueryAll(doc, "//script/@src")
	if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		var src = htmlquery.InnerText(node)
		url, err := urlutil.Parse(src)
		if err != nil {
			continue
		}

		if url.IsRelative {
			url.Host = baseUrl.Host
			url.Scheme = baseUrl.Scheme
		}
		scripts = append(scripts, url.String())
	}

	for _, script := range scripts {
		if strings.Contains(script, "/_buildManifest.js") {
			log.Info("Detected Next.JS pages router! Getting all scripts from %s", script)
			nextScripts, err := frameworks.GetPagesRouterScripts(script, timeout)
			if err != nil {
				spin.Stop()
				return nil, err
			}

			for _, nextScript := range nextScripts {
				if slices.Contains(scripts, nextScript) {
					continue
				}
				scripts = append(scripts, nextScript)
			}
		}
	}

	log.Info("Got %d scripts, now running scans on them", len(scripts))

	supabaseResults := make([]supabaseScanResult, 0, len(scripts))
	secretMatches := make([]SecretMatch, 0)
	endpoints := make([]string, 0)
	// dedupe secrets and endpoints across every script, not just within one.
	seenSecrets := make(map[string]struct{})
	seenEndpoints := make(map[string]struct{})
	for _, script := range scripts {
		charmlog.Debugf("Scanning %s", script)
		req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, script, http.NoBody)
		if err != nil {
			charmlog.Warnf("Failed to create request: %s", err)
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			charmlog.Warnf("Failed to fetch script: %s", err)
			continue
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		resp.Body.Close()
		if err != nil {
			charmlog.Errorf("Failed to read script body: %s", err)
			continue
		}
		content := string(bodyBytes)

		charmlog.Debugf("Running supabase scanner on %s", script)
		scriptSupabaseResults, err := ScanSupabase(content, script, timeout)

		if err != nil {
			charmlog.Errorf("Error while scanning supabase: %s", err)
		}

		if scriptSupabaseResults != nil {
			supabaseResults = append(supabaseResults, scriptSupabaseResults...)
		}

		// reuse the same script buffer for credential and endpoint extraction.
		for _, match := range ScanSecrets(content, script) {
			key := match.Rule + "\x00" + match.Match
			if _, ok := seenSecrets[key]; ok {
				continue
			}
			seenSecrets[key] = struct{}{}
			secretMatches = append(secretMatches, match)
			log.Warn("found %s in %s", match.Rule, script)
		}

		for _, endpoint := range ExtractEndpoints(content, script) {
			if _, ok := seenEndpoints[endpoint]; ok {
				continue
			}
			seenEndpoints[endpoint] = struct{}{}
			endpoints = append(endpoints, endpoint)
		}
	}

	spin.Stop()

	if len(endpoints) > 0 {
		log.Info("extracted %d endpoints", len(endpoints))
	}

	result := JavascriptScanResult{
		SupabaseResults:      supabaseResults,
		FoundEnvironmentVars: map[string]string{},
		SecretMatches:        secretMatches,
		Endpoints:            endpoints,
	}

	log.Complete(len(supabaseResults)+len(secretMatches)+len(endpoints), "found")

	return &result, nil
}
