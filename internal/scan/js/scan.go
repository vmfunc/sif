/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (Celeste Hickenlooper), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package js

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/antchfx/htmlquery"
	charmlog "github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/output"
	"github.com/dropalldatabases/sif/internal/scan/js/frameworks"
	urlutil "github.com/projectdiscovery/utils/url"
)

type JavascriptScanResult struct {
	SupabaseResults      []supabaseScanResult `json:"supabase_results"`
	FoundEnvironmentVars map[string]string    `json:"environment_variables"`
}

// ResultType implements the ScanResult interface.
func (r *JavascriptScanResult) ResultType() string { return "js" }

func JavascriptScan(url string, timeout time.Duration, threads int, logdir string) (*JavascriptScanResult, error) {
	log := output.Module("JS")
	log.Start()

	spin := output.NewSpinner("Scanning JavaScript files")
	spin.Start()

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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		spin.Stop()
		return nil, err
	}
	defer resp.Body.Close()

	var sb strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
	}
	html := sb.String()

	doc, err := htmlquery.Parse(strings.NewReader(html))
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
			nextScripts, err := frameworks.GetPagesRouterScripts(script)
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
	for _, script := range scripts {
		charmlog.Debugf("Scanning %s", script)
		req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, script, http.NoBody)
		if err != nil {
			charmlog.Warnf("Failed to create request: %s", err)
			continue
		}
		resp, err := http.DefaultClient.Do(req)
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
		scriptSupabaseResults, err := ScanSupabase(content, script)

		if err != nil {
			charmlog.Errorf("Error while scanning supabase: %s", err)
		}

		if scriptSupabaseResults != nil {
			supabaseResults = append(supabaseResults, scriptSupabaseResults...)
		}
	}

	spin.Stop()

	result := JavascriptScanResult{
		SupabaseResults:      supabaseResults,
		FoundEnvironmentVars: map[string]string{},
	}

	log.Complete(len(supabaseResults), "found")

	return &result, nil
}
