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
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// crawlSite serves a small link graph:
//
//	/      -> links /a and an off-host page; references script.js, form action /submit
//	/a     -> links /b
//	/b     -> links /c (only reachable at depth 3)
//	/c     -> leaf
func crawlSite(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	// no robots restrictions; colly fetches this before crawling.
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`<html><body>
			<a href="/a">a</a>
			<a href="https://off-host.example/x">off</a>
			<script src="/script.js"></script>
			<form action="/submit"></form>
		</body></html>`))
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<a href="/b">b</a>`))
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<a href="/c">c</a>`))
	})
	mux.HandleFunc("/c", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`leaf`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func urlsContain(urls []string, want string) bool {
	for i := 0; i < len(urls); i++ {
		if urls[i] == want {
			return true
		}
	}
	return false
}

func TestCrawl_FindsLinkedPagesAndAssets(t *testing.T) {
	srv := crawlSite(t)

	result, err := Crawl(srv.URL, 3, 5*time.Second, "")
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	// links, scripts and forms must all be recorded, resolved to absolute urls.
	wants := []string{
		srv.URL + "/a",
		srv.URL + "/b",
		srv.URL + "/c",
		srv.URL + "/script.js",
		srv.URL + "/submit",
	}
	for _, w := range wants {
		if !urlsContain(result.URLs, w) {
			t.Errorf("expected crawl to find %q, got %v", w, result.URLs)
		}
	}

	// AllowedDomains must keep the off-host link out of the result set.
	if urlsContain(result.URLs, "https://off-host.example/x") {
		t.Errorf("off-host link should be excluded, got %v", result.URLs)
	}
}

func TestCrawl_RespectsDepth(t *testing.T) {
	srv := crawlSite(t)

	// depth 1: only links found on the root page (/a, /script.js, /submit) are
	// recorded; /b lives one hop deeper and must not appear.
	result, err := Crawl(srv.URL, 1, 5*time.Second, "")
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	if !urlsContain(result.URLs, srv.URL+"/a") {
		t.Errorf("depth 1 should find /a, got %v", result.URLs)
	}
	if urlsContain(result.URLs, srv.URL+"/b") {
		t.Errorf("depth 1 must not reach /b, got %v", result.URLs)
	}
	if urlsContain(result.URLs, srv.URL+"/c") {
		t.Errorf("depth 1 must not reach /c, got %v", result.URLs)
	}
}

func TestCrawl_Dedupes(t *testing.T) {
	// a page that links the same target twice must yield a single entry.
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dup" {
			_, _ = w.Write([]byte(`leaf`))
			return
		}
		_, _ = w.Write([]byte(`<a href="/dup">1</a><a href="/dup">2</a>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	result, err := Crawl(srv.URL, 2, 5*time.Second, "")
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	count := 0
	for _, u := range result.URLs {
		if u == srv.URL+"/dup" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected /dup once after dedupe, got %d in %v", count, result.URLs)
	}
}

func TestCrawl_ResultType(t *testing.T) {
	r := &CrawlResult{}
	if r.ResultType() != "crawl" {
		t.Errorf("ResultType = %q, want crawl", r.ResultType())
	}
}

// a hostile page that fans out to far more links than any real page would
// must not turn a bounded-depth crawl into an unbounded one: colly's
// MaxRequests budget was left at 0 (unlimited) and Crawl set no Limit rule,
// so every fanned-out child got fetched regardless of depth. maxCrawlRequests
// now caps the total number of pages (i.e. actual HTTP fetches) a single
// Crawl call will make. Note the child pages are leaves with no links of
// their own, so this exercises the request cap rather than the (unbounded,
// by design) count of links recorded off of a single already-fetched page.
func TestCrawl_BoundsRequestFanout(t *testing.T) {
	fanout := maxCrawlRequests + 500
	var hits int64

	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		if r.URL.Path != "/" {
			_, _ = w.Write([]byte("leaf"))
			return
		}
		for i := 0; i < fanout; i++ {
			_, _ = fmt.Fprintf(w, `<a href="/p/%d">l</a>`, i)
		}
	})
	target := httptest.NewServer(mux)
	defer target.Close()

	if _, err := Crawl(target.URL, 1, 30*time.Second, ""); err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	// +1 for the root page itself; the rest must be capped at maxCrawlRequests.
	if got, want := atomic.LoadInt64(&hits), int64(maxCrawlRequests+1); got > want {
		t.Errorf("expected at most %d requests (request cap), server received %d", want, got)
	}
}

// robots.txt is intentionally NOT honored: sif is a recon/pentest crawler and
// Disallow rules are not a scope boundary it should respect. This pins the
// intentional behavior so it isn't "fixed" into a partial robots.txt
// implementation by accident later.
func TestCrawl_DoesNotHonorRobots(t *testing.T) {
	var secretHits int64
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/secret" {
			atomic.AddInt64(&secretHits, 1)
			_, _ = w.Write([]byte("leaf"))
			return
		}
		_, _ = fmt.Fprint(w, `<a href="/secret">s</a>`)
	})
	target := httptest.NewServer(mux)
	defer target.Close()

	if _, err := Crawl(target.URL, 2, 5*time.Second, ""); err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if got := atomic.LoadInt64(&secretHits); got == 0 {
		t.Errorf("expected Disallow:/ path to be fetched (robots.txt is not honored), got %d hits", got)
	}
}
