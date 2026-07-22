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
	"net/http"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gocolly/colly/v2"

	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
)

// maxCrawlPages bounds total fetches independent of depth: MaxDepth caps
// recursion depth but not breadth, so a link-heavy page (pagination, faceted
// search) otherwise grows request count as branching^depth with no ceiling.
const maxCrawlPages = 500

// CrawlResult holds the deduped set of urls discovered by the spider.
type CrawlResult struct {
	URLs      []string `json:"urls"`
	Truncated bool     `json:"truncated,omitempty"` // hit maxCrawlPages before the spider ran out of links
}

func (r *CrawlResult) ResultType() string { return "crawl" }

// compile-time check so a result-type drift fails the build, not a run.
var _ ScanResult = (*CrawlResult)(nil)

// maxCrawlRequests caps the total pages a single Crawl call will fetch, so a
// hostile page fanning out to an attacker-controlled number of links can't
// turn a bounded-depth crawl into an unbounded one (b^d).
const maxCrawlRequests = 2000

// maxRedirectHops mirrors net/http's own default redirect cap, which we lose
// once we install a custom CheckRedirect below.
const maxRedirectHops = 10

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
		colly.MaxRequests(maxCrawlRequests),
	)
	// reuse the shared transport so proxy/-H/rate-limit still apply, but scope
	// redirects ourselves: colly's CheckRedirect only re-checks AllowedDomains,
	// which matches on hostname alone, so a same-host redirect to a different
	// port would still be followed. also re-cap the hop count, since installing
	// a custom CheckRedirect drops net/http's own 10-redirect default.
	collector.SetClient(&http.Client{
		Timeout:   timeout,
		Transport: httpx.Client(timeout).Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirectHops {
				return fmt.Errorf("stopped after %d redirects", maxRedirectHops)
			}
			if req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("redirect to %q leaves crawl scope %q", req.URL, via[0].URL.Host)
			}
			return nil
		},
	})

	// dedupe across the concurrent callbacks colly may fire.
	var mu sync.Mutex
	seen := make(map[string]struct{})

	// visited caps the total pages fetched (see maxCrawlPages); atomic since
	// colly's callbacks can fire from multiple goroutines.
	var visited int64
	var truncated int32

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

	// count every request toward the budget (the seed included) and abort once
	// it is exceeded, before the dial, so a link-heavy target can't run away.
	collector.OnRequest(func(r *colly.Request) {
		if atomic.AddInt64(&visited, 1) > maxCrawlPages {
			atomic.StoreInt32(&truncated, 1)
			r.Abort()
		}
	})

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

	result := &CrawlResult{URLs: sortedKeys(seen), Truncated: atomic.LoadInt32(&truncated) != 0}
	if result.Truncated {
		log.Warn("crawl hit the %d-page budget and stopped early; results are partial", maxCrawlPages)
	}

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
