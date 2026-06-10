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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMatcher_Matches(t *testing.T) {
	tests := []struct {
		name string
		opts DirlistOptions
		meta responseMeta
		body string
		want bool
	}{
		{
			// default behavior: 404/403 drop, everything else surfaces
			name: "default keeps 200",
			opts: DirlistOptions{},
			meta: responseMeta{status: 200, size: 10, words: 2},
			want: true,
		},
		{
			name: "default drops 404",
			opts: DirlistOptions{},
			meta: responseMeta{status: 404, size: 9, words: 1},
			want: false,
		},
		{
			name: "default drops 403",
			opts: DirlistOptions{},
			meta: responseMeta{status: 403, size: 9, words: 1},
			want: false,
		},
		{
			// -mc is allow-list: only listed codes survive
			name: "mc allowlist keeps listed",
			opts: DirlistOptions{MatchCodes: "200,301"},
			meta: responseMeta{status: 301, size: 0, words: 0},
			want: true,
		},
		{
			name: "mc allowlist drops unlisted 200 already excluded",
			opts: DirlistOptions{MatchCodes: "301"},
			meta: responseMeta{status: 200, size: 5, words: 1},
			want: false,
		},
		{
			name: "fc drops listed code",
			opts: DirlistOptions{FilterCodes: "500"},
			meta: responseMeta{status: 500, size: 5, words: 1},
			want: false,
		},
		{
			// with an explicit -fc and no -mc, the implicit 404/403 filter is not
			// added, so a 200 still surfaces
			name: "fc leaves others",
			opts: DirlistOptions{FilterCodes: "500"},
			meta: responseMeta{status: 200, size: 5, words: 1},
			want: true,
		},
		{
			name: "fs drops listed size",
			opts: DirlistOptions{FilterSizes: "1024"},
			meta: responseMeta{status: 200, size: 1024, words: 50},
			want: false,
		},
		{
			name: "fw drops listed word count",
			opts: DirlistOptions{FilterWords: "7"},
			meta: responseMeta{status: 200, size: 40, words: 7},
			want: false,
		},
		{
			name: "fr drops body match",
			opts: DirlistOptions{FilterRegex: "not found"},
			meta: responseMeta{status: 200, size: 9, words: 2},
			body: "page not found",
			want: false,
		},
		{
			name: "fr keeps non-match",
			opts: DirlistOptions{FilterRegex: "not found"},
			meta: responseMeta{status: 200, size: 5, words: 1},
			body: "welcome",
			want: true,
		},
		{
			// filter precedence: -mc would keep it, but a size filter drops it
			name: "filter wins over match",
			opts: DirlistOptions{MatchCodes: "200", FilterSizes: "12"},
			meta: responseMeta{status: 200, size: 12, words: 3},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := newMatcher(&tt.opts)
			if err != nil {
				t.Fatalf("newMatcher: %v", err)
			}
			if got := m.Matches(tt.meta, []byte(tt.body)); got != tt.want {
				t.Errorf("Matches(%+v, %q) = %v, want %v", tt.meta, tt.body, got, tt.want)
			}
		})
	}
}

func TestMatcher_BaselineSuppresses(t *testing.T) {
	m, err := newMatcher(&DirlistOptions{})
	if err != nil {
		t.Fatalf("newMatcher: %v", err)
	}
	// a calibrated soft-404 shape drops an identical response
	m.baselines = []responseMeta{{status: 200, size: 42, words: 5}}

	soft := responseMeta{status: 200, size: 42, words: 5}
	if m.Matches(soft, nil) {
		t.Error("baseline-matching response should be suppressed")
	}
	// a real page with a different size must still surface
	livePage := responseMeta{status: 200, size: 99, words: 12}
	if !m.Matches(livePage, nil) {
		t.Error("distinct response should not be suppressed by baseline")
	}
}

func TestNewMatcher_InvalidFlags(t *testing.T) {
	tests := []struct {
		name string
		opts DirlistOptions
	}{
		{"bad mc", DirlistOptions{MatchCodes: "abc"}},
		{"bad fc", DirlistOptions{FilterCodes: "20x"}},
		{"bad fs", DirlistOptions{FilterSizes: "big"}},
		{"bad fw", DirlistOptions{FilterWords: "-"}},
		{"bad regex", DirlistOptions{FilterRegex: "("}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newMatcher(&tt.opts); err == nil {
				t.Errorf("newMatcher(%+v) expected error, got nil", tt.opts)
			}
		})
	}
}

func TestExpandWords(t *testing.T) {
	tests := []struct {
		name  string
		words []string
		exts  string
		want  []string
	}{
		{
			name:  "no extensions unchanged",
			words: []string{"admin", "login"},
			exts:  "",
			want:  []string{"admin", "login"},
		},
		{
			name:  "appends each extension and keeps bare",
			words: []string{"config"},
			exts:  "php,bak,env",
			want:  []string{"config", "config.php", "config.bak", "config.env"},
		},
		{
			name:  "tolerates leading dot and spaces",
			words: []string{"db"},
			exts:  " .sql , bak ",
			want:  []string{"db", "db.sql", "db.bak"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandWords(tt.words, tt.exts)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("expandWords(%v, %q) = %v, want %v", tt.words, tt.exts, got, tt.want)
			}
		})
	}
}

// softWildcardApp serves a couple of real paths and a catch-all soft-404: every
// unknown path returns a fixed 200 body, the SPA pattern that floods dirlist.
func softWildcardApp() *httptest.Server {
	const softBody = "<html><body>app shell - route handled client side</body></html>"
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>admin control panel dashboard here</body></html>"))
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>please sign in with your account credentials now</body></html>"))
	})
	// catch-all: anything else gets the identical soft-404 shell
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" || r.URL.Path == "/login" {
			return
		}
		w.Write([]byte(softBody))
	})
	return httptest.NewServer(mux)
}

func TestDirlist_CalibrationSuppressesWildcard(t *testing.T) {
	srv := softWildcardApp()
	defer srv.Close()

	// the wordlist mixes the two real paths with several bogus ones the catch-all
	// answers with the soft-404 shell.
	dir := t.TempDir()
	wordlist := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\nlogin\nnope\nbogus\nmissing\n"), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}

	// without calibration every bogus path is a soft-404 200 and floods output
	noAC, err := Dirlist("small", srv.URL, 5*time.Second, 3, "", DirlistOptions{Wordlist: wordlist})
	if err != nil {
		t.Fatalf("Dirlist (no -ac): %v", err)
	}
	if len(noAC) < 5 {
		t.Fatalf("expected the wildcard to flood all 5 paths without -ac, got %d", len(noAC))
	}

	// with -ac the soft-404 baseline is learned and the bogus paths drop
	withAC, err := Dirlist("small", srv.URL, 5*time.Second, 3, "", DirlistOptions{
		Wordlist:  wordlist,
		Calibrate: true,
	})
	if err != nil {
		t.Fatalf("Dirlist (-ac): %v", err)
	}

	got := pathSet(withAC)
	if !has(got, "/admin") || !has(got, "/login") {
		t.Errorf("real paths admin/login must still surface with -ac, got %v", sortedKeys(got))
	}
	for _, bogus := range []string{"/nope", "/bogus", "/missing"} {
		if has(got, bogus) {
			t.Errorf("soft-404 path %s should be suppressed by -ac, got %v", bogus, sortedKeys(got))
		}
	}
}

func TestDirlist_ExtensionExpansion(t *testing.T) {
	// the server only answers config.php; the bare word and other extensions hit
	// the catch-all soft-404, so -e must be what surfaces config.php.
	const realBody = "<?php // database connection settings live here ?>"
	mux := http.NewServeMux()
	mux.HandleFunc("/config.php", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(realBody))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // hard 404 for everything but config.php
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	wordlist := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(wordlist, []byte("config\n"), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}

	results, err := Dirlist("small", srv.URL, 5*time.Second, 2, "", DirlistOptions{
		Wordlist:   wordlist,
		Extensions: "php,bak",
	})
	if err != nil {
		t.Fatalf("Dirlist: %v", err)
	}

	got := pathSet(results)
	if !has(got, "/config.php") {
		t.Errorf("expected -e to surface config.php, got %v", sortedKeys(got))
	}
	if has(got, "/config") || has(got, "/config.bak") {
		t.Errorf("only config.php exists; bare word and .bak are 404s, got %v", sortedKeys(got))
	}
}

func TestDirlist_LocalWordlistOverridesSize(t *testing.T) {
	// a local -w must be used verbatim and never touch directoryURL; point the
	// remote at a sink that fails the test if it's ever hit.
	orig := directoryURL
	directoryURL = "http://127.0.0.1:0/should-not-be-fetched/"
	defer func() { directoryURL = orig }()

	mux := http.NewServeMux()
	mux.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>top secret area found</html>"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	wordlist := filepath.Join(dir, "custom.txt")
	if err := os.WriteFile(wordlist, []byte("secret\nabsent\n"), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}

	results, err := Dirlist("large", srv.URL, 5*time.Second, 2, "", DirlistOptions{Wordlist: wordlist})
	if err != nil {
		t.Fatalf("Dirlist: %v", err)
	}

	got := pathSet(results)
	if !has(got, "/secret") {
		t.Errorf("expected the custom wordlist to find /secret, got %v", sortedKeys(got))
	}
	if has(got, "/absent") {
		t.Errorf("/absent is a 404 and should not surface, got %v", sortedKeys(got))
	}
}

// pathSet collects each result's url path for membership checks. it reuses the
// package-level sortedKeys (crawl.go) for deterministic failure output.
func pathSet(results DirectoryResults) map[string]struct{} {
	set := make(map[string]struct{}, len(results))
	for i := 0; i < len(results); i++ {
		if idx := strings.Index(results[i].Url, "://"); idx >= 0 {
			rest := results[i].Url[idx+len("://"):]
			if slash := strings.Index(rest, "/"); slash >= 0 {
				set[rest[slash:]] = struct{}{}
				continue
			}
		}
		set[results[i].Url] = struct{}{}
	}
	return set
}

// has is a tiny readability helper for set membership in assertions.
func has(set map[string]struct{}, key string) bool {
	_, ok := set[key]
	return ok
}
