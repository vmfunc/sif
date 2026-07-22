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
	"strings"
	"testing"
	"time"
)

const (
	// reused across the artifact fixtures below.
	fakeSHA = "1d69b25b0d808e0e78ce366cd2ccf897e43783be"
	// the all-zero sha git writes as the previous value of a ref's first reflog.
	zeroSHA = "0000000000000000000000000000000000000000"
)

func TestLooksLikeGit(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		want bool
	}{
		{"head ref", ".git/HEAD", "ref: refs/heads/main\n", true},
		{"head detached", ".git/HEAD", fakeSHA + "\n", true},
		{"config core", ".git/config", "[core]\n\trepositoryformatversion = 0\n", true},
		{"index magic", ".git/index", "DIRC\x00\x00\x00\x02", true},
		{"ref sha", ".git/refs/remotes/origin/main", fakeSHA + "\n", true},
		{"ref sha256", ".git/refs/remotes/origin/main", strings.Repeat("a", 64) + "\n", true},
		{"reflog line", ".git/logs/refs/remotes/origin/main", zeroSHA + " " + fakeSHA + " a <a@b> 1 -0700\tx\n", true},
		{"gitignore text", ".gitignore", "node_modules/\n", true},
		{"gitignore comment lead", ".gitignore", "# build output\n*.log\n", true},
		// a .gitignore can legitimately open with a '[' character-class glob
		// (common in .net repos), so the fallback must not treat '[' as json.
		{"gitignore bracket glob", ".gitignore", "[Bb]in/\n[Oo]bj/\n", true},

		// a server that answers every path with the same shell is the dominant
		// false positive; none of these are the requested artifact.
		{"head json shell", ".git/HEAD", `{"error":"not found"}`, false},
		{"head text shell", ".git/HEAD", "Not Found", false},
		{"head html shell", ".git/HEAD", "<!doctype html><html></html>", false},
		{"config json shell", ".git/config", `{"error":"not found"}`, false},
		{"index json shell", ".git/index", `{"error":"nope"}`, false},
		{"ref json shell", ".git/refs/remotes/origin/main", `{"ok":true}`, false},
		{"reflog text shell", ".git/logs/refs/remotes/origin/main", "Page not found", false},
		{"gitignore json shell", ".gitignore", `{"error":"not found"}`, false},
		{"gitignore json array shell", ".gitignore", `[{"error":"not found"}]`, false},
		{"gitignore html shell", ".gitignore", "<!doctype html><html></html>", false},
		// known limit: .gitignore has no fixed shape, so a plain-text soft-404 is
		// indistinguishable from a real ignore file and is accepted. the structured
		// artifacts (HEAD/config/index/refs) carry the detection weight.
		{"gitignore plaintext soft404 accepted", ".gitignore", "Not Found", true},
		{"empty body", ".git/HEAD", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeGit(tt.path, []byte(tt.body)); got != tt.want {
				t.Errorf("looksLikeGit(%q, %q) = %v, want %v", tt.path, tt.body, got, tt.want)
			}
		})
	}
}

// gitFixtureApp backs TestGit_SuppressesCatchAll: real .git/HEAD plus a catch-all 200 json shell everywhere else.
func gitFixtureApp() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ref: refs/heads/main\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/HEAD" {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":"not found"}`))
	})
	return httptest.NewServer(mux)
}

func TestGit_SuppressesCatchAll(t *testing.T) {
	target := gitFixtureApp()
	defer target.Close()

	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(".git/HEAD\n.git/config\n.git/index\n"))
	}))
	defer list.Close()

	orig := gitURL
	gitURL = list.URL + "/"
	t.Cleanup(func() { gitURL = orig })

	found, err := Git(target.URL, 5*time.Second, 3, "")
	if err != nil {
		t.Fatalf("Git: %v", err)
	}

	if len(found) != 1 {
		t.Fatalf("expected only the real .git/HEAD to surface, got %d: %v", len(found), found)
	}
	if !strings.HasSuffix(found[0], "/.git/HEAD") {
		t.Errorf("expected .git/HEAD, got %q", found[0])
	}
}
