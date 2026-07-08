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
	"testing"
	"time"
)

// an html soft-404 served with a mixed-case content-type must still be gated
// out. mime types are case-insensitive, so the html filter can't be case-bound
// or the same error page reads as an exposed .git repo.
func TestGit_MixedCaseHTMLContentTypeNotFound(t *testing.T) {
	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(".git/config\n"))
	}))
	defer list.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "Text/HTML; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>404 not found</body></html>"))
	}))
	defer target.Close()

	orig := gitURL
	gitURL = list.URL + "/"
	defer func() { gitURL = orig }()

	found, err := Git(target.URL, 5*time.Second, 1, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("mixed-case text/html soft-404 must not count as git, got %v", found)
	}
}

// the html filter must not over-suppress: a genuinely exposed .git is usually
// served as text/plain, octet-stream or with no content-type, and all of those
// must still be reported. guards the case-insensitive filter from silently
// swallowing real findings.
func TestGit_NonHTMLContentTypesStillFound(t *testing.T) {
	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(".git/config\n"))
	}))
	defer list.Close()

	for _, ct := range []string{"text/plain", "application/octet-stream", ""} {
		t.Run(ct, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if ct != "" {
					w.Header().Set("Content-Type", ct)
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("[core]\n\trepositoryformatversion = 0\n"))
			}))
			defer target.Close()

			orig := gitURL
			gitURL = list.URL + "/"
			defer func() { gitURL = orig }()

			found, err := Git(target.URL, 5*time.Second, 1, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(found) != 1 {
				t.Errorf("real git served as %q must be reported, got %v", ct, found)
			}
		})
	}
}
