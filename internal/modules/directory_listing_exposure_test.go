package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runDirectoryListingModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func TestDirectoryListingExposureModule(t *testing.T) {
	const dl = "../../modules/recon/directory-listing-exposure.yaml"

	t.Run("a real nginx autoindex page is flagged", func(t *testing.T) {
		body := `<html>
<head><title>Index of /uploads/</title></head>
<body>
<h1>Index of /uploads/</h1><hr><pre><a href="../">../</a>
<a href="invoice-2024.pdf">invoice-2024.pdf</a>            03-Jul-2026 09:12  842311
<a href="dump.sql">dump.sql</a>                     03-Jul-2026 09:14   19204
</pre><hr></body>
</html>`
		res := runDirectoryListingModule(t, dl, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a finding for a real nginx autoindex page")
		}
	})

	t.Run("a real apache mod_autoindex page is flagged", func(t *testing.T) {
		body := `<html>
 <head>
  <title>Index of /backup</title>
 </head>
 <body>
<h1>Index of /backup</h1>
<table>
<tr><th><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td></tr>
<tr><td valign="top"><img src="/icons/compressed.gif" alt="[   ]"></td><td><a href="site-backup.tar.gz">site-backup.tar.gz</a></td><td align="right">03-Jul-2026 09:10  </td><td align="right"> 41M</td></tr>
</table>
<address>Apache/2.4.52 (Ubuntu) Server at example.com Port 80</address>
</body></html>`
		res := runDirectoryListingModule(t, dl, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a finding for a real apache mod_autoindex page")
		}
	})

	t.Run("a real python http.server listing is flagged", func(t *testing.T) {
		body := `<!DOCTYPE HTML>
<html>
<head>
<meta charset="utf-8">
<title>Directory listing for /files/</title>
</head>
<body>
<h1>Directory listing for /files/</h1>
<hr>
<ul>
<li><a href="secrets.txt">secrets.txt</a></li>
</ul>
<hr>
</body>
</html>`
		res := runDirectoryListingModule(t, dl, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a finding for a real python http.server listing")
		}
	})

	t.Run("a real IIS directory browsing page is flagged", func(t *testing.T) {
		body := `<html>
<head><title>files.example.com - /data/</title></head>
<body>
<H1>files.example.com - /data/</H1><hr>
<pre><A HREF="/data/">[To Parent Directory]</A><br><br>
7/3/2026  9:12 AM        &lt;dir&gt; archive<br>
7/3/2026  9:14 AM             19204 dump.sql<br>
</pre>
<hr>
</body>
</html>`
		res := runDirectoryListingModule(t, dl, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a finding for a real IIS directory browsing page")
		}
	})

	t.Run("a real caddy file_server browse page is flagged", func(t *testing.T) {
		body := `<!DOCTYPE html>
<html>
<head><title>/media/</title></head>
<body>
	<header>
		<div class="wrapper">
			<div class="breadcrumbs">Folder Path</div>
				<h1><a href="/">/</a>media/</h1>
			</div>
		</header>
		<div class="wrapper">
			<main>
				<div class='listing'>
				<div class="entry"><a href="masters.zip">masters.zip</a></div>
				</div>
			</main>
		</div>
</body>
</html>`
		res := runDirectoryListingModule(t, dl, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a finding for a real caddy file_server browse page")
		}
	})

	t.Run("a real apache non-fancy (plain) mod_autoindex page is flagged", func(t *testing.T) {
		// IndexOptions without FancyIndexing: a <ul>/<li> list, no sort-links,
		// and the parent-dir anchor is rendered with a leading space
		// (mod_autoindex.c emits `"\"> "` before the text). the parent-dir
		// alternative must tolerate that surrounding whitespace.
		body := `<html>
 <head><title>Index of /backup</title></head>
 <body>
<h1>Index of /backup</h1>
<ul><li><a href="/"> Parent Directory</a></li>
<li><a href="site-backup.tar.gz"> site-backup.tar.gz</a></li>
</ul>
<address>Apache/2.4.52 (Ubuntu) Server at example.com Port 80</address>
</body></html>`
		res := runDirectoryListingModule(t, dl, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a finding for a real apache non-fancy mod_autoindex page")
		}
	})

	t.Run("a blog post with a slash in its index-of title is not flagged", func(t *testing.T) {
		body := `<html>
<head><title>Index of /r/programming favorites</title></head>
<body>
<h1>Index of /r/programming favorites</h1>
<p>A curated index of the best posts from /r/programming this year, sorted by
upvotes. Bookmark this page.</p>
</body>
</html>`
		if res := runDirectoryListingModule(t, dl, 200, body); len(res.Findings) > 0 {
			t.Errorf("a prose blog with a slash in the title should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an IIS tutorial mentioning the parent-directory link is not flagged", func(t *testing.T) {
		body := `<html>
<head><title>Tutorial - /wwwroot setup guide</title></head>
<body>
<h1>Setting up directory browsing</h1>
<p>Once enabled, users will see a [To Parent Directory] link at the top of the
listing that navigates up one level.</p>
</body>
</html>`
		if res := runDirectoryListingModule(t, dl, 200, body); len(res.Findings) > 0 {
			t.Errorf("an IIS tutorial mentioning the bare parent-dir string should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a blog post whose title says index of is not flagged", func(t *testing.T) {
		body := `<html>
<head><title>Index of Human Knowledge: A History</title></head>
<body>
<h1>Index of Human Knowledge: A History</h1>
<p>This article is an index of the great libraries of the ancient world, from
Alexandria to Nineveh, and how each collection organized its scrolls.</p>
</body>
</html>`
		if res := runDirectoryListingModule(t, dl, 200, body); len(res.Findings) > 0 {
			t.Errorf("a prose page mentioning 'index of' should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a custom 403 page is not flagged", func(t *testing.T) {
		body := `<html>
<head><title>403 Forbidden</title></head>
<body>
<h1>Access Denied</h1>
<p>You do not have permission to view this directory listing.</p>
</body>
</html>`
		if res := runDirectoryListingModule(t, dl, 403, body); len(res.Findings) > 0 {
			t.Errorf("a custom 403 should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a custom 404 page is not flagged", func(t *testing.T) {
		body := `<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>`
		if res := runDirectoryListingModule(t, dl, 404, body); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an SPA shell page is not flagged", func(t *testing.T) {
		body := `<!DOCTYPE html>
<html>
<head><title>My App</title></head>
<body>
<div id="root"></div>
<script src="/static/js/main.abc123.js"></script>
</body>
</html>`
		if res := runDirectoryListingModule(t, dl, 200, body); len(res.Findings) > 0 {
			t.Errorf("an SPA shell should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runDirectoryListingModule(t, dl, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 body should not match, got %d findings", len(res.Findings))
		}
	})
}
