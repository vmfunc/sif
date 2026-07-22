package scan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestCrawlBudgetCapsUnboundedBreadth guards against the request count Crawl
// issues growing without bound. MaxDepth only caps recursion depth; without a
// breadth budget, a page that hands back many fresh links per level (ordinary
// pagination/faceted-search shapes, not just a deliberate trap) drives the
// fetch count to branching^depth. This pins the total at maxCrawlPages instead.
func TestCrawlBudgetCapsUnboundedBreadth(t *testing.T) {
	const branching = 40 // links per page
	var reqCount int64

	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&reqCount, 1)
		// every page hands back `branching` brand-new, never-before-seen paths
		// keyed off the requesting path, so colly's exact-url dedupe can't
		// collapse them - the pagination/calendar-trap shape.
		prefix := r.URL.Path
		if prefix == "/" {
			prefix = ""
		}
		for i := 0; i < branching; i++ {
			fmt.Fprintf(w, `<a href="%s/%d">x</a>`, prefix, i)
		}
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// depth=3 would otherwise fetch 1 + branching + branching^2 = 1641 pages;
	// the budget must cut that off at maxCrawlPages regardless of depth.
	result, err := Crawl(srv.URL, 3, 5*time.Second, "")
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	got := atomic.LoadInt64(&reqCount)
	t.Logf("depth=3 branching=%d -> %d requests (budget %d), truncated=%v",
		branching, got, maxCrawlPages, result.Truncated)

	if got > maxCrawlPages {
		t.Fatalf("expected the page budget to cap requests at %d, got %d", maxCrawlPages, got)
	}
	if !result.Truncated {
		t.Fatalf("expected Truncated=true once the budget is hit, got false")
	}
}

// TestCrawlBudgetDoesNotTruncateSmallSites is the negative case: an ordinary
// small site well under the budget crawls to completion and reports
// Truncated=false, so the new cap doesn't regress normal runs.
func TestCrawlBudgetDoesNotTruncateSmallSites(t *testing.T) {
	srv := crawlSite(t)
	defer srv.Close()

	result, err := Crawl(srv.URL, 2, 2*time.Second, "")
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if result.Truncated {
		t.Fatalf("small site should not hit the page budget, got Truncated=true (urls=%v)", result.URLs)
	}
}
