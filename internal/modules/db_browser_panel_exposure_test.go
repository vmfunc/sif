package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runDBBrowserModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func dbBrowserExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestDBBrowserPanelExposureModules(t *testing.T) {
	const mongoExpress = "../../modules/info/mongo-express-panel.yaml"
	const redisCommander = "../../modules/info/redis-commander-panel.yaml"
	const pgweb = "../../modules/info/pgweb-panel.yaml"

	// verbatim fragments from mongo-express/mongo-express lib/views/layout.html and index.html (master)
	mongoExpressBody := `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Home - Mongo Express</title>
  <link href="/public/css/style.css" rel="stylesheet" />
</head>
<body class="pb-3">
<nav id="navbar" class="navbar navbar-expand-lg navbar-light bg-light sticky-top p-0">
  <a class="navbar-brand" href="/">
    <img src="/public/img/mongo-express-logo.png" width="30" height="30" alt="" />
    Mongo Express
  </a>
</nav>
<div class="card mb-3">
  <div class="card-header">
    <h4 class="d-inline-block">Databases</h4>
  </div>
  <ul class="list-group list-group-flush">
    <li class="list-group-item p-1">admin</li>
    <li class="list-group-item p-1">app_production</li>
  </ul>
</div>
<div class="card mb-3">
  <h4 class="card-header">Server status</h4>
  <table class="table table-bordered table-striped m-0">
    <tr>
      <td><strong>Hostname</strong></td>
      <td>mongo-0</td>
      <td><strong>MongoDB Version</strong></td>
      <td>7.0.2</td>
    </tr>
  </table>
</div>
<script src="/public/js/vendor.js"></script>
<script type="text/javascript">
  globalThis.ME_SETTINGS = {"gridFSEnabled":false};
</script>
</body>
</html>`

	// verbatim fragments from joeferner/redis-commander lib/app.js title default and
	// web/views/layout.ejs + web/views/home/home.ejs (master)
	redisCommanderBody := `<!DOCTYPE html>
<html>
<head>
  <title>Redis Commander: Home</title>
  <link rel="icon" type="image/png" href="favicon.png">
  <script src="scripts/redisCommander.js"></script>
</head>
<body>
<div class="navbar navbar-fixed-top">
  <div class="navbar-inner">
    <a class="brand" href="./"><img src="images/RedisCommandLogo.png"/></a>
  </div>
</div>
<div id="app-container">
  <div id="sideBar">
    <div id="keyTreeActions">
      <button class="btn btn-success btn-mini" onclick="refreshTree()">Refresh</button>
    </div>
    <div id="keyTree"></div>
  </div>
</div>
</body>
</html>`

	// verbatim fragments from sosedoff/pgweb static/index.html (main)
	pgwebBody := `<!DOCTYPE html>
<html lang="en" xml:lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
  <title>pgweb</title>
  <script type="text/javascript" src="static/js/ace.js"></script>
  <script type="text/javascript" src="static/js/ace-pgsql.js"></script>
  <script type="text/javascript" src="static/js/app.js"></script>
</head>
<body>
  <div id="main">
    <div id="nav">
      <ul>
        <li id="table_content">Rows</li>
        <li id="table_connection">Connection</li>
      </ul>
      <div class="connection-actions">
        <a href="#" id="close_connection" class="btn btn-default btn-sm">Disconnect</a>
      </div>
    </div>
  </div>
</body>
</html>`

	t.Run("an exposed mongo-express serves its database list and is flagged and versioned", func(t *testing.T) {
		res := runDBBrowserModule(t, mongoExpress, 200, mongoExpressBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a mongo-express finding")
		}
		if v := dbBrowserExtract(res, "mongodb_version"); v != "7.0.2" {
			t.Errorf("mongodb_version=%q, want 7.0.2", v)
		}
	})

	t.Run("an exposed redis-commander key browser is flagged", func(t *testing.T) {
		res := runDBBrowserModule(t, redisCommander, 200, redisCommanderBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a redis-commander finding")
		}
	})

	t.Run("an exposed pgweb instance is flagged", func(t *testing.T) {
		res := runDBBrowserModule(t, pgweb, 200, pgwebBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a pgweb finding")
		}
	})

	t.Run("a generic app.js reference alone is not pgweb", func(t *testing.T) {
		body := `<html><head><title>pgweb</title><script src="static/js/app.js"></script></head><body>hi</body></html>`
		if res := runDBBrowserModule(t, pgweb, 200, body); len(res.Findings) > 0 {
			t.Errorf("missing ace-pgsql.js should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a bare mongo express logo mention without the settings global is not mongo-express", func(t *testing.T) {
		body := `<html><body><img src="mongo-express-logo.png"></body></html>`
		if res := runDBBrowserModule(t, mongoExpress, 200, body); len(res.Findings) > 0 {
			t.Errorf("missing ME_SETTINGS should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("the unauth connection form without a database list is not a mongo-express exposure", func(t *testing.T) {
		// login.html extends layout.html, so it carries ME_SETTINGS, the title
		// and the logo but never the Databases listing. flagging it would be a
		// false positive: no data is served.
		body := `<html><head><title>Log in - Mongo Express</title></head><body>` +
			`<img src="/public/img/mongo-express-logo.png"><form>password</form>` +
			`<script>globalThis.ME_SETTINGS = {};</script></body></html>`
		if res := runDBBrowserModule(t, mongoExpress, 200, body); len(res.Findings) > 0 {
			t.Errorf("connection form should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a bare redisCommander.js script reference without any panel markup is not redis-commander", func(t *testing.T) {
		body := `<html><head><script src="scripts/redisCommander.js"></script></head><body>404 not found</body></html>`
		if res := runDBBrowserModule(t, redisCommander, 200, body); len(res.Findings) > 0 {
			t.Errorf("missing panel markers should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic soft-404 shell is silent on all three modules", func(t *testing.T) {
		body := `<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested resource could not be found.</p></body></html>`
		for _, f := range []string{mongoExpress, redisCommander, pgweb} {
			if res := runDBBrowserModule(t, f, 200, body); len(res.Findings) > 0 {
				t.Errorf("%s: soft-404 shell should not match, got %d findings", f, len(res.Findings))
			}
		}
	})

	t.Run("a non-200 status is silent on all three modules", func(t *testing.T) {
		for _, f := range []string{mongoExpress, redisCommander, pgweb} {
			if res := runDBBrowserModule(t, f, 500, "internal server error"); len(res.Findings) > 0 {
				t.Errorf("%s: 500 status should not match, got %d findings", f, len(res.Findings))
			}
		}
	})
}
