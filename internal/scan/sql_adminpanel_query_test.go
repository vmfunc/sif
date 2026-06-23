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

// genericDefaultPanelTypes are the sqlAdminPaths entries with no product-specific
// case in isAdminPanel, so they fall through to the default keyword branch.
var genericDefaultPanelTypes = []string{
	"SQL Interface", "Database Interface", "Database Admin", "MySQL Admin",
	"SQL Manager", "WebSQL", "SQLWeb", "MongoDB Interface", "Redis Interface",
}

// an ordinary javascript page is not a database admin panel. "query" used to
// match the default branch via jQuery/querySelector, flagging every js site.
func TestIsAdminPanel_GenericJSPageNotFlagged(t *testing.T) {
	pages := []struct{ name, body string }{
		{"jquery script tag", `<script src="/assets/jquery-3.6.0.min.js"></script>`},
		{"querySelector call", `<script>document.querySelector(".nav").focus()</script>`},
		{"jquery invocation", `<script>jQuery(function(){ jQuery("#a").hide(); });</script>`},
		{"search query word", "<form><input name='q' placeholder='search query'></form>"},
		{"graphql query const", `<script>const QUERY = "{ user { id } }";</script>`},
	}
	for _, p := range pages {
		for _, pt := range genericDefaultPanelTypes {
			if isAdminPanel(p.body, pt) {
				t.Errorf("%s wrongly flagged as %q admin panel", p.name, pt)
			}
		}
	}
}

// dropping "query" must not reduce recall: real db interfaces still match via
// the sibling keywords (database/sql/mysql/postgresql/mongodb).
func TestIsAdminPanel_RealGenericPanelsStillDetected(t *testing.T) {
	cases := []struct{ name, body string }{
		{"database manager", "<title>Database Manager</title>"},
		{"sql console", "<h1>SQL Console</h1>"},
		{"mysql admin", "<title>MySQL Administration</title>"},
		{"postgresql browser", "<div>PostgreSQL database browser</div>"},
		{"mongodb express", "<title>mongodb express</title>"},
		{"sql query interface", "<div>SQL Query Interface</div>"},
	}
	for _, c := range cases {
		if !isAdminPanel(c.body, "Database Interface") {
			t.Errorf("%s should still be detected as a database interface", c.name)
		}
	}
}

// the precise change: a lone "query" no longer triggers, but "query" alongside
// a db keyword still does, carried by the sibling.
func TestIsAdminPanel_QueryRemovalPrecise(t *testing.T) {
	if isAdminPanel("<title>Query Console</title>", "Database Interface") {
		t.Error(`lone "query" should no longer trigger the default branch`)
	}
	if !isAdminPanel("<title>SQL Query Tool</title>", "Database Interface") {
		t.Error(`"query" with "sql" should still detect via "sql"`)
	}
}

// the default-branch change must not disturb the product-specific cases.
func TestIsAdminPanel_ExplicitCasesUnaffected(t *testing.T) {
	cases := []struct {
		panelType string
		body      string
		want      bool
	}{
		{"phpMyAdmin", "<title>phpMyAdmin</title>", true},
		{"phpMyAdmin", "<script>var pma_token='1';</script>", true},
		{"phpMyAdmin", "<title>Home</title>", false},
		{"Adminer", "<title>Adminer</title>", true},
		{"Adminer", "nothing relevant", false},
		{"pgAdmin", "<title>pgAdmin 4</title>", true},
		{"phpPgAdmin", "<h1>phpPgAdmin</h1>", true},
		{"RockMongo", "<title>RockMongo</title>", true},
		{"Redis Commander", "<title>Redis Commander</title>", true},
		{"phpRedisAdmin", "<h1>phpRedisAdmin</h1>", true},
		{"phpMyAdmin", `<script src="jquery.js"></script>`, false},
	}
	for _, c := range cases {
		if got := isAdminPanel(c.body, c.panelType); got != c.want {
			t.Errorf("isAdminPanel(%q, %q) = %v, want %v", c.body, c.panelType, got, c.want)
		}
	}
}

// end to end: a catch-all that serves a jquery page at every path (the common
// soft-404-as-200 case) must not yield any admin-panel finding.
func TestSQL_JQueryCatchAllNotReported(t *testing.T) {
	jq := `<!doctype html><html><head>
<script src="/static/jquery.min.js"></script></head>
<body><script>document.querySelector("#app")</script><p>Welcome</p></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(jq))
	}))
	defer srv.Close()

	result, err := SQL(srv.URL, 5*time.Second, 4, "", false)
	if err != nil {
		t.Fatalf("SQL: %v", err)
	}
	// SQL returns a nil result when nothing is found, which is the pass case here.
	if result != nil && len(result.AdminPanels) != 0 {
		t.Errorf("jquery catch-all produced %d admin-panel finding(s): %+v",
			len(result.AdminPanels), result.AdminPanels)
	}
}

// end to end: a real phpMyAdmin install is still reported.
func TestSQL_RealPhpMyAdminReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/phpmyadmin/" {
			_, _ = w.Write([]byte("<html><title>phpMyAdmin</title></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result, err := SQL(srv.URL, 5*time.Second, 4, "", false)
	if err != nil {
		t.Fatalf("SQL: %v", err)
	}
	if result == nil {
		t.Fatal("expected a phpMyAdmin finding, got nil result")
	}
	found := false
	for _, p := range result.AdminPanels {
		if p.Type == "phpMyAdmin" {
			found = true
		}
	}
	if !found {
		t.Errorf("real phpMyAdmin not reported; panels=%+v", result.AdminPanels)
	}
}

// end to end: a genuine generic db interface (db-topical body at a db path) is
// still reported, so the change did not over-tighten the default branch.
func TestSQL_RealGenericPanelReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/db/" {
			_, _ = w.Write([]byte("<html><title>Database Manager</title><body>MySQL server status</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result, err := SQL(srv.URL, 5*time.Second, 4, "", false)
	if err != nil {
		t.Fatalf("SQL: %v", err)
	}
	if result == nil || len(result.AdminPanels) == 0 {
		t.Error("a real database interface at /db/ should still be reported")
	}
}
