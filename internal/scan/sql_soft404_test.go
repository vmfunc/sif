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
	"testing"
	"time"
)

// representative bodies. these are not padded to force a size delta: a generic
// homepage and a real admin login simply have different content, hence different
// shapes. the catch-all body carries no db keyword so the comparison turns on the
// baseline, not on isAdminPanel.
const (
	catchAllHome = `<!DOCTYPE html><html><head><title>Acme</title></head>` +
		`<body><nav>Home About Contact</nav><main>Welcome to Acme.</main></body></html>`

	realPMALogin = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
		`<title>phpMyAdmin</title><link rel="stylesheet" href="phpmyadmin.css.php"></head>` +
		`<body class="loginform"><form method="post" action="index.php"><fieldset>` +
		`<legend>Log in to phpMyAdmin</legend>` +
		`<label>Username</label><input type="text" name="pma_username">` +
		`<label>Password</label><input type="password" name="pma_password">` +
		`<input type="submit" value="Go"></fieldset></form></body></html>`

	realDBAdmin = `<!DOCTYPE html><html><head><title>Database Manager</title></head>` +
		`<body><h1>MySQL Server 8.0</h1><table><tr><th>Database</th><th>Tables</th></tr>` +
		`<tr><td>app_production</td><td>42</td></tr></table>` +
		`<form action="/run"><textarea name="sql">SELECT 1</textarea><button>Run</button></form>` +
		`</body></html>`
)

// countAdminPanels is nil-safe: SQL returns a nil result when nothing is found.
func countAdminPanels(r *SQLResult) int {
	if r == nil {
		return 0
	}
	return len(r.AdminPanels)
}

// hasPanelType reports whether a panel of the given type was found.
func hasPanelType(r *SQLResult, panelType string) bool {
	if r == nil {
		return false
	}
	for _, p := range r.AdminPanels {
		if p.Type == panelType {
			return true
		}
	}
	return false
}

// a 200 catch-all (the SPA wildcard) is calibrated as a baseline shape.
func TestCalibrateSQLBaseline_CatchAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(catchAllHome))
	}))
	defer srv.Close()

	baselines := calibrateSQLBaseline(srv.URL, &http.Client{Timeout: 5 * time.Second})
	if len(baselines) == 0 {
		t.Fatal("a 200 catch-all should produce at least one baseline shape")
	}
}

// a server that hard-404s every bogus path needs no baseline (status already filters).
func TestCalibrateSQLBaseline_HardNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	baselines := calibrateSQLBaseline(srv.URL, &http.Client{Timeout: 5 * time.Second})
	if len(baselines) != 0 {
		t.Errorf("hard-404 server should yield no baseline, got %d", len(baselines))
	}
}

// with -ac on, a 200 catch-all serving a db-topical page at every path yields no
// admin-panel finding once the wildcard shape is calibrated.
func TestSQL_CatchAllSuppressed(t *testing.T) {
	page := "<html><body>database dashboard for our service</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()

	result, err := SQL(srv.URL, 5*time.Second, 4, "", true)
	if err != nil {
		t.Fatalf("SQL: %v", err)
	}
	if n := countAdminPanels(result); n != 0 {
		t.Errorf("catch-all produced %d admin-panel finding(s) with -ac, want 0", n)
	}
}

// a 403 WAF that blanket-blocks with a db-mentioning page is also a catch-all and
// must be suppressed (covers the 403 branch of the status set).
func TestSQL_403WAFCatchAllSuppressed(t *testing.T) {
	page := "Request blocked: possible sql injection attempt detected"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()

	result, err := SQL(srv.URL, 5*time.Second, 4, "", true)
	if err != nil {
		t.Fatalf("SQL: %v", err)
	}
	if n := countAdminPanels(result); n != 0 {
		t.Errorf("403 WAF catch-all produced %d admin-panel finding(s) with -ac, want 0", n)
	}
}

// suppression is opt-in: with -ac off (the default) the same catch-all is still
// reported, matching dirlist's behavior.
func TestSQL_CalibrateDisabledStillReports(t *testing.T) {
	page := "<html><body>database dashboard for our service</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()

	result, err := SQL(srv.URL, 5*time.Second, 4, "", false)
	if err != nil {
		t.Fatalf("SQL: %v", err)
	}
	if countAdminPanels(result) == 0 {
		t.Error("with -ac off, the catch-all should still be reported (suppression is opt-in)")
	}
}

// a real phpMyAdmin hosted on a catch-all is still reported under -ac: a genuine
// login page is a different shape than the wildcard homepage, so it is not dropped.
func TestSQL_RealPanelAmongCatchAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/phpmyadmin/" {
			_, _ = w.Write([]byte(realPMALogin))
			return
		}
		_, _ = w.Write([]byte(catchAllHome))
	}))
	defer srv.Close()

	result, err := SQL(srv.URL, 5*time.Second, 4, "", true)
	if err != nil {
		t.Fatalf("SQL: %v", err)
	}
	if !hasPanelType(result, "phpMyAdmin") {
		t.Errorf("real phpMyAdmin on a catch-all should still be reported; panels=%d",
			countAdminPanels(result))
	}
}

// a real generic interface (a distinct db admin page at /db/) is still reported
// under -ac, so calibration does not over-suppress genuine findings.
func TestSQL_RealGenericPanelAmongCatchAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/db/" {
			_, _ = w.Write([]byte(realDBAdmin))
			return
		}
		_, _ = w.Write([]byte(catchAllHome))
	}))
	defer srv.Close()

	result, err := SQL(srv.URL, 5*time.Second, 4, "", true)
	if err != nil {
		t.Fatalf("SQL: %v", err)
	}
	if countAdminPanels(result) == 0 {
		t.Error("a real database interface at /db/ on a catch-all should still be reported")
	}
}

// the normal case (no catch-all): a host that 404s everything except a real
// phpMyAdmin still reports it, since calibration finds no baseline.
func TestSQL_HardNotFoundRealPanelReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/phpmyadmin/" {
			_, _ = w.Write([]byte(realPMALogin))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result, err := SQL(srv.URL, 5*time.Second, 4, "", true)
	if err != nil {
		t.Fatalf("SQL: %v", err)
	}
	if !hasPanelType(result, "phpMyAdmin") {
		t.Error("phpMyAdmin on a non-catch-all host should be reported")
	}
}

// characterization of a known limitation (shared with dirlist): a catch-all that
// reflects the request path varies its shape per path, so exact-shape calibration
// cannot suppress it. this pins current behavior on purpose: if it fails, the
// matching got stricter (the gap closed) and the test should be updated to expect 0.
func TestSQL_ReflectedPathCatchAllNotSuppressed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>no such page: %s (database)</body></html>", r.URL.Path)
	}))
	defer srv.Close()

	result, err := SQL(srv.URL, 5*time.Second, 4, "", true)
	if err != nil {
		t.Fatalf("SQL: %v", err)
	}
	if countAdminPanels(result) == 0 {
		t.Error("reflected-path catch-all was suppressed; the gap closed, update this test to expect 0")
	}
}
