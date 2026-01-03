/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (vmfunc), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package js

import (
	"bufio"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/antchfx/htmlquery"
	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/pkg/scan/js/frameworks"
	urlutil "github.com/projectdiscovery/utils/url"
)

type JavascriptScanResult struct {
	SupabaseResults      []supabaseScanResult `json:"supabase_results"`
	FoundEnvironmentVars map[string]string    `json:"environment_variables"`
}

func JavascriptScan(url string, timeout time.Duration, threads int, logdir string) (*JavascriptScanResult, error) {
	jslog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "🚧 JavaScript",
	}).With("url", url)

	baseUrl, err := urlutil.Parse(url)
	if err != nil {
		return nil, err
	}
	resp, err := http.Get(url)
	if err != nil {
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
			jslog.Infof("Detected Next.JS pages router! Getting all scripts from %s", script)
			nextScripts, err := frameworks.GetPagesRouterScripts(script)
			if err != nil {
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

	jslog.Infof("Got %d scripts, now running scans on them", len(scripts))

	supabaseResults := make([]supabaseScanResult, 0, len(scripts))
	for _, script := range scripts {
		jslog.Infof("Scanning %s", script)
		resp, err := http.Get(script)
		if err != nil {
			jslog.Warnf("Failed to fetch script: %s", err)
			continue
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			jslog.Errorf("Failed to read script body: %s", err)
			continue
		}
		content := string(bodyBytes)

		jslog.Infof("Running supabase scanner on %s", script)
		scriptSupabaseResults, err := ScanSupabase(content, script)

		if err != nil {
			jslog.Errorf("Error while scanning supabase: %s", err)
		}

		if scriptSupabaseResults != nil {
			supabaseResults = append(supabaseResults, scriptSupabaseResults...)
		}
	}

	result := JavascriptScanResult{
		SupabaseResults:      supabaseResults,
		FoundEnvironmentVars: map[string]string{},
	}

	return &result, nil
}
