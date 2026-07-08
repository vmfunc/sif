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

package frameworks

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetPagesRouterScriptsCapturesAllChunksPerRoute(t *testing.T) {
	// a route array can list several chunks; every one is a real script to scan,
	// not just the first element after the opening bracket.
	manifest := `self.__BUILD_MANIFEST={"/":["static/chunks/pages/index-a.js","static/chunks/shared-b.js"]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(manifest))
	}))
	defer srv.Close()

	scripts, err := GetPagesRouterScripts(srv.URL + "/_buildManifest.js")
	if err != nil {
		t.Fatalf("GetPagesRouterScripts: %v", err)
	}

	found := func(needle string) bool {
		for _, s := range scripts {
			if strings.Contains(s, needle) {
				return true
			}
		}
		return false
	}
	if !found("index-a.js") || !found("shared-b.js") {
		t.Errorf("want both chunks index-a.js and shared-b.js, got %v", scripts)
	}
}

func TestGetPagesRouterScriptsReadsPastLongLine(t *testing.T) {
	// a manifest token past bufio's 64k cap must not truncate the read and
	// drop the script references that follow it.
	huge := strings.Repeat("x", bufio.MaxScanTokenSize+1)
	manifest := `["static/early.js"]` + "\n" + huge + "\n" + `["static/late.js"]`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(manifest))
	}))
	defer srv.Close()

	scripts, err := GetPagesRouterScripts(srv.URL + "/_buildManifest.js")
	if err != nil {
		t.Fatalf("GetPagesRouterScripts: %v", err)
	}

	found := func(needle string) bool {
		for _, s := range scripts {
			if strings.Contains(s, needle) {
				return true
			}
		}
		return false
	}
	if !found("early.js") || !found("late.js") {
		t.Errorf("want both early.js and late.js, got %v", scripts)
	}
}

func TestGetPagesRouterScriptsRealisticManifest(t *testing.T) {
	// routes map to multi-chunk arrays, shared chunks are IIFE args, and
	// non-chunk .js strings appear in __rewrites and sortedPages; only the
	// former may end up in scripts, or a rewrite destination could steer a fetch.
	manifest := `self.__BUILD_MANIFEST=(function(a,b,c){return{` +
		`__rewrites:{afterFiles:[{"source":"/proxy/legacy.js","destination":"https://cdn.evil.example/tracker.js"}],beforeFiles:[],fallback:[]},` +
		`"/":[a,b,"static/chunks/pages/index-1a2b.js"],` +
		`"/_error":[a,"static/chunks/pages/_error-3c4d.js"],` +
		`"/blog/[slug]":[a,b,c,"static/chunks/pages/blog/[slug]-5e6f.js"],` +
		`sortedPages:["/","/_app","/_error","/blog/[slug]"],` +
		`ampFirstPages:[]` +
		`}}("static/chunks/webpack-9f8e.js","static/chunks/main-0d1c.js","static/chunks/framework-2b3a.js"));` +
		`self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB();`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(manifest))
	}))
	defer srv.Close()

	scripts, err := GetPagesRouterScripts(srv.URL + "/_buildManifest.js")
	if err != nil {
		t.Fatalf("GetPagesRouterScripts: %v", err)
	}

	found := func(needle string) bool {
		for _, s := range scripts {
			if strings.Contains(s, needle) {
				return true
			}
		}
		return false
	}

	// every real chunk, including the trailing IIFE-arg shared chunks
	wantChunks := []string{
		"static/chunks/pages/index-1a2b.js",
		"static/chunks/pages/_error-3c4d.js",
		"static/chunks/pages/blog/[slug]-5e6f.js",
		"static/chunks/webpack-9f8e.js",
		"static/chunks/main-0d1c.js",
		"static/chunks/framework-2b3a.js",
	}
	for _, c := range wantChunks {
		if !found(c) {
			t.Errorf("missing chunk %q, got %v", c, scripts)
		}
	}

	// no non-chunk .js string may leak into the fetch list
	for _, bad := range []string{"legacy.js", "tracker.js", "cdn.evil.example"} {
		if found(bad) {
			t.Errorf("false positive: captured non-chunk %q in %v", bad, scripts)
		}
	}
}
