package js

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/antchfx/htmlquery"
	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/pkg/scan/js/frameworks"
	urlutil "github.com/projectdiscovery/utils/url"
)

func JavascriptScan(url string, timeout time.Duration, threads int, logdir string) {
	baseUrl, err := urlutil.Parse(url)
	if err != nil {
		return
	}
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	var html string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		html += scanner.Text()
	}

	doc, err := htmlquery.Parse(strings.NewReader(html))
	if err != nil {
		return
	}

	var scripts []string
	nodes, err := htmlquery.QueryAll(doc, "//script/@src")
	if err != nil {
		return
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
			nextScripts, err := frameworks.GetPagesRouterScripts(script)
			if err != nil {
				return
			}

			for _, nextScript := range nextScripts {
				if slices.Contains(scripts, nextScript) {
					continue
				}
				scripts = append(scripts, nextScript)
			}
		}
	}

	log.Debugf("Got all scripts: %s, now running scans on them", scripts)

	for _, script := range scripts {
		log.Debugf("Scanning %s", script)
		resp, err := http.Get(script)
		if err != nil {
			fmt.Println(err)
			continue
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		content := string(bodyBytes)

		supabaseResults, err := ScanSupabase(content)

		if err != nil {
			log.Debugf("Error while scanning supabase: %s", err)
		}

		if supabaseResults != nil {
			marshalled, err := json.Marshal(supabaseResults)
			if err != nil {
				continue
			}

			log.Debugf("Supabase results: %s", marshalled)
		}
	}
}
