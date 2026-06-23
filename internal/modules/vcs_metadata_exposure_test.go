package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runVCSModule(t *testing.T, file string, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule(file)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	res, err := modules.ExecuteHTTPModule(context.Background(), srv.URL, def, modules.Options{
		Timeout: 5 * time.Second,
		Threads: 2,
	})
	if err != nil {
		t.Fatalf("execute %s: %v", file, err)
	}
	return res
}

func vcsExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestVCSMetadataExposureModules(t *testing.T) {
	const svn = "../../modules/recon/svn-exposure.yaml"
	const hg = "../../modules/recon/mercurial-exposure.yaml"
	const bzr = "../../modules/recon/bazaar-exposure.yaml"

	svnWcDb := "SQLite format 3\x00" + strings.Repeat("\x00", 80) +
		"CREATE TABLE WCROOT (id INTEGER PRIMARY KEY);" +
		"CREATE TABLE REPOSITORY (root TEXT, uuid TEXT);" +
		"\x01root\x00https://svn.example.com/myrepo/trunk\x00"

	hgRequires := "revlogv1\nstore\nfncache\ndotencode\ngeneraldelta\nsparserevlog\n"

	bzrFormat := "Bazaar-NG meta directory, format 1\n"

	t.Run("an exposed svn wc.db leaks the repository url", func(t *testing.T) {
		res := runVCSModule(t, svn, 200, svnWcDb)
		if len(res.Findings) == 0 {
			t.Fatal("expected an svn finding")
		}
		if v := vcsExtract(res, "svn_repository"); v != "https://svn.example.com/myrepo/trunk" {
			t.Errorf("svn_repository=%q, want https://svn.example.com/myrepo/trunk", v)
		}
	})

	t.Run("an exposed mercurial requires is flagged", func(t *testing.T) {
		res := runVCSModule(t, hg, 200, hgRequires)
		if len(res.Findings) == 0 {
			t.Fatal("expected a mercurial finding")
		}
		if v := vcsExtract(res, "hg_requirement"); v != "revlogv1" {
			t.Errorf("hg_requirement=%q, want revlogv1", v)
		}
	})

	t.Run("an exposed bazaar branch-format is flagged", func(t *testing.T) {
		res := runVCSModule(t, bzr, 200, bzrFormat)
		if len(res.Findings) == 0 {
			t.Fatal("expected a bazaar finding")
		}
		if v := vcsExtract(res, "bzr_format"); v != "Bazaar-NG meta directory, format 1" {
			t.Errorf("bzr_format=%q, want the meta directory signature", v)
		}
	})

	t.Run("a generic sqlite database without svn tables is not flagged", func(t *testing.T) {
		body := "SQLite format 3\x00" + strings.Repeat("\x00", 80) +
			"CREATE TABLE users (id INTEGER, name TEXT, email TEXT);"
		if res := runVCSModule(t, svn, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic sqlite db should not match svn, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic sqlite with a nodes table is not an svn working copy", func(t *testing.T) {
		body := "SQLite format 3\x00" + strings.Repeat("\x00", 80) +
			"CREATE TABLE NODES (id INTEGER PRIMARY KEY, parent INTEGER, label TEXT);"
		if res := runVCSModule(t, svn, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic nodes table should not match svn, got %d findings", len(res.Findings))
		}
	})

	t.Run("an svn magic that is not at byte zero is not flagged", func(t *testing.T) {
		body := "<!DOCTYPE html><html><body><pre>SQLite format 3 WCROOT REPOSITORY</pre></body></html>"
		if res := runVCSModule(t, svn, 200, body); len(res.Findings) > 0 {
			t.Errorf("an unanchored magic should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a page naming mercurial without the requires format is not flagged", func(t *testing.T) {
		body := "this project uses mercurial for distributed version control"
		if res := runVCSModule(t, hg, 200, body); len(res.Findings) > 0 {
			t.Errorf("prose naming mercurial should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page demonstrating hg requires is not a leak", func(t *testing.T) {
		body := "<!DOCTYPE html><html><body><pre>revlogv1\nstore\ndotencode</pre></body></html>"
		if res := runVCSModule(t, hg, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html hg tutorial should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a bazaar marketplace page is not a repository", func(t *testing.T) {
		body := "Welcome to the Bazaar, the finest open air marketplace in town"
		if res := runVCSModule(t, bzr, 200, body); len(res.Findings) > 0 {
			t.Errorf("a marketplace page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page demonstrating bzr branch-format is not a leak", func(t *testing.T) {
		body := "<!DOCTYPE html><html><body><pre>Bazaar-NG meta directory, format 1</pre></body></html>"
		if res := runVCSModule(t, bzr, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html bzr tutorial should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{svn, hg, bzr} {
			if res := runVCSModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{svn, hg, bzr} {
			if res := runVCSModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
