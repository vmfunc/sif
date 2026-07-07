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

package scan

import (
	"fmt"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/gocolly/colly/v2"

	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
)

// CrawlResult holds the deduped set of urls discovered by the spider.
type CrawlResult struct {
	URLs []string `json:"urls"`
}

func (r *CrawlResult) ResultType() string { return "crawl" }

// compile-time check so a result-type drift fails the build, not a run.
var _ ScanResult = (*CrawlResult)(nil)

// Crawl spiders the target up to depth, following same-host links/scripts/forms.
// all traffic flows through the shared httpx client so proxy/headers/rate-limit
// apply. robots.txt is intentionally NOT honored: this is a recon/pentest
// crawler and Disallow rules are not a scope boundary we want to respect.
func Crawl(targetURL string, depth int, timeout time.Duration, logdir string) (*CrawlResult, error) {
	log := output.Module("CRAWL")
	log.Start()

	sanitizedURL := stripScheme(targetURL)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "web crawl"); err != nil {
			log.Error("error creating log file: %v", err)
			return nil, fmt.Errorf("create crawl log: %w", err)
		}
	}

	// the host bounds the crawl; without it colly would wander the whole web.
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("parse target url %q: %w", targetURL, err)
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("target url %q has no host", targetURL)
	}

	collector := colly.NewCollector(
		colly.MaxDepth(depth),
		colly.AllowedDomains(host),
	)
	// reuse the shared client so proxy/cookie/-H/rate-limit are honored and the
	// configured timeout applies to every fetch, robots.txt included.
	collector.SetClient(httpx.Client(timeout))

	// dedupe across the concurrent callbacks colly may fire.
	var mu sync.Mutex
	seen := make(map[string]struct{})

	record := func(raw string) {
		if raw == "" {
			return
		}
		// keep the result set scoped to the target host; off-host assets
		// (cdns, third-party links) are noise for an in-scope crawl.
		if u, err := url.Parse(raw); err != nil || u.Hostname() != host {
			return
		}
		mu.Lock()
		if _, ok := seen[raw]; !ok {
			seen[raw] = struct{}{}
			log.Success("found: %s", output.Highlight.Render(raw))
			if logdir != "" {
				_ = logger.Write(sanitizedURL, logdir, raw+"\n")
			}
		}
		mu.Unlock()
	}

	// links drive recursion; scripts/forms are recorded but not followed.
	collector.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		record(link)
		// Visit enforces AllowedDomains/MaxDepth itself, so off-host or
		// too-deep links are dropped without us re-checking.
		_ = e.Request.Visit(link)
	})
	collector.OnHTML("script[src]", func(e *colly.HTMLElement) {
		record(e.Request.AbsoluteURL(e.Attr("src")))
	})
	collector.OnHTML("form[action]", func(e *colly.HTMLElement) {
		record(e.Request.AbsoluteURL(e.Attr("action")))
	})

	collector.OnError(func(_ *colly.Response, e error) {
		// a single bad page shouldn't abort the crawl; note it and move on.
		log.Warn("crawl error: %v", e)
	})

	if err := collector.Visit(targetURL); err != nil {
		log.Error("crawl failed: %v", err)
		return nil, fmt.Errorf("visit %q: %w", targetURL, err)
	}
	collector.Wait()

	result := &CrawlResult{URLs: sortedKeys(seen)}

	log.Complete(len(result.URLs), "urls")
	return result, nil
}

// sortedKeys returns the map keys in a stable order so output is deterministic.
func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
