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
	"sync"
	"testing"
)

func TestIsAdminPanel_phpMyAdmin(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"contains phpMyAdmin", "<html><title>phpMyAdmin</title></html>", true},
		{"contains pma_", "<script>var pma_token = '123';</script>", true},
		{"empty body", "", false},
		{"unrelated content", "<html><title>Hello World</title></html>", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAdminPanel(tt.body, "phpMyAdmin")
			if result != tt.expected {
				t.Errorf("isAdminPanel(%q, 'phpMyAdmin') = %v, want %v", tt.body, result, tt.expected)
			}
		})
	}
}

func TestIsAdminPanel_Adminer(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"contains Adminer", "<html><title>Adminer</title></html>", true},
		{"lowercase adminer", "<div>adminer version 4.8</div>", true},
		{"empty body", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAdminPanel(tt.body, "Adminer")
			if result != tt.expected {
				t.Errorf("isAdminPanel(%q, 'Adminer') = %v, want %v", tt.body, result, tt.expected)
			}
		})
	}
}

func TestIsAdminPanel_GenericDatabase(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"contains database", "<html><title>Database Manager</title></html>", true},
		{"contains sql", "<div>SQL Query Interface</div>", true},
		{"contains mysql", "<script>mysql_query()</script>", true},
		{"contains postgresql", "<div>PostgreSQL Admin</div>", true},
		{"empty body", "", false},
		{"unrelated content", "<html><title>Blog</title></html>", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAdminPanel(tt.body, "Database Interface")
			if result != tt.expected {
				t.Errorf("isAdminPanel(%q, 'Database Interface') = %v, want %v", tt.body, result, tt.expected)
			}
		})
	}
}

func TestSQLResult_Fields(t *testing.T) {
	result := SQLResult{
		AdminPanels: []SQLAdminPanel{
			{
				URL:    "http://example.com/phpmyadmin/",
				Type:   "phpMyAdmin",
				Status: 200,
			},
		},
		DatabaseErrors: []SQLDatabaseError{
			{
				URL:          "http://example.com/?id=1'",
				DatabaseType: "MySQL",
				ErrorPattern: "mysql.*error",
			},
		},
	}

	if len(result.AdminPanels) != 1 {
		t.Errorf("expected 1 admin panel, got %d", len(result.AdminPanels))
	}
	if result.AdminPanels[0].Type != "phpMyAdmin" {
		t.Errorf("expected type 'phpMyAdmin', got '%s'", result.AdminPanels[0].Type)
	}
	if len(result.DatabaseErrors) != 1 {
		t.Errorf("expected 1 database error, got %d", len(result.DatabaseErrors))
	}
	if result.DatabaseErrors[0].DatabaseType != "MySQL" {
		t.Errorf("expected database type 'MySQL', got '%s'", result.DatabaseErrors[0].DatabaseType)
	}
}

func TestDatabaseErrorPatterns_MySQL(t *testing.T) {
	testCases := []struct {
		name     string
		body     string
		expected bool
	}{
		{"mysql error", "MySQL Error: Something went wrong", true},
		{"mysql syntax", "You have an error in your SQL syntax", true},
		{"mysql fetch", "Warning: mysql_fetch_array()", true},
		{"no error", "Welcome to our website", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			found := false
			for _, pattern := range databaseErrorPatterns {
				if pattern.pattern.MatchString(tc.body) {
					found = true
					break
				}
			}
			if found != tc.expected {
				t.Errorf("pattern match for %q = %v, want %v", tc.body, found, tc.expected)
			}
		})
	}
}

func TestDatabaseErrorPatterns_PostgreSQL(t *testing.T) {
	testCases := []struct {
		name     string
		body     string
		expected bool
	}{
		{"postgresql error", "PostgreSQL Error: connection failed", true},
		{"pg_query", "Warning: pg_query(): Query failed", true},
		{"unterminated string", "ERROR: unterminated quoted string", true},
		{"no error", "Welcome to our website", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			found := false
			for _, pattern := range databaseErrorPatterns {
				if pattern.pattern.MatchString(tc.body) {
					found = true
					break
				}
			}
			if found != tc.expected {
				t.Errorf("pattern match for %q = %v, want %v", tc.body, found, tc.expected)
			}
		})
	}
}

func TestDatabaseErrorPatterns_SQLServer(t *testing.T) {
	testCases := []struct {
		name     string
		body     string
		expected bool
	}{
		{"mssql error", "MSSQL Error: invalid query", true},
		{"sql server error", "Microsoft SQL Server Error", true},
		{"unclosed quote", "Unclosed quotation mark after the character string", true},
		{"no error", "Welcome to our website", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			found := false
			for _, pattern := range databaseErrorPatterns {
				if pattern.pattern.MatchString(tc.body) {
					found = true
					break
				}
			}
			if found != tc.expected {
				t.Errorf("pattern match for %q = %v, want %v", tc.body, found, tc.expected)
			}
		})
	}
}

func TestDatabaseErrorPatterns_Oracle(t *testing.T) {
	testCases := []struct {
		name     string
		body     string
		expected bool
	}{
		{"ora error code", "ORA-00942: table or view does not exist", true},
		{"oracle error", "Oracle Error: invalid identifier", true},
		{"no error", "Welcome to our website", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			found := false
			for _, pattern := range databaseErrorPatterns {
				if pattern.pattern.MatchString(tc.body) {
					found = true
					break
				}
			}
			if found != tc.expected {
				t.Errorf("pattern match for %q = %v, want %v", tc.body, found, tc.expected)
			}
		})
	}
}

func TestSQLAdminPanelDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/phpmyadmin/":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><title>phpMyAdmin</title></html>"))
		case "/adminer/":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><title>Adminer</title></html>"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// this is a basic test to verify the server mock works
	resp, err := http.Get(server.URL + "/phpmyadmin/")
	if err != nil {
		t.Fatalf("failed to get phpmyadmin: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 for /phpmyadmin/, got %d", resp.StatusCode)
	}
}

func TestSQLDatabaseErrorDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") == "1'" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("MySQL Error: You have an error in your SQL syntax"))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Welcome to our website"))
		}
	}))
	defer server.Close()

	// verify server returns mysql error for injection attempt
	resp, err := http.Get(server.URL + "/?id=1'")
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

// TestCheckDatabaseErrors_SharedTemplateNotFlagged proves a db error string
// present on every response, including non-injection paths, is not reported.
func TestCheckDatabaseErrors_SharedTemplateNotFlagged(t *testing.T) {
	const sharedTemplate = "<html>Debug: mysql_fetch_array() failed on this handler</html>"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sharedTemplate))
	}))
	defer server.Close()

	client := server.Client()
	result := &SQLResult{}
	seen := make(map[string]bool)
	var mu sync.Mutex

	// fetched directly rather than through checkDatabaseErrors: this test only
	// covers suppression of later probes, not the homepage's own content.
	resp, err := client.Get(server.URL + "/")
	if err != nil {
		t.Fatalf("failed to fetch baseline: %v", err)
	}
	defer resp.Body.Close()
	baselineBody := sharedTemplate

	checkDatabaseErrors(client, server.URL+"/login", server.URL, result, "", &mu, seen, baselineBody)
	checkDatabaseErrors(client, server.URL+"/?id=1'", server.URL, result, "", &mu, seen, baselineBody)

	if len(result.DatabaseErrors) != 0 {
		t.Errorf("expected no differential database errors, got %d: %+v", len(result.DatabaseErrors), result.DatabaseErrors)
	}
}

// TestCheckDatabaseErrors_DifferentialErrorFlagged proves the fix does not
// suppress a real, injection-caused disclosure: only the probed path shows
// the error string, the baseline page does not.
func TestCheckDatabaseErrors_DifferentialErrorFlagged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.URL.RawQuery == "id=1'" {
			w.Write([]byte("MySQL Error: You have an error in your SQL syntax"))
			return
		}
		w.Write([]byte("Welcome to our website"))
	}))
	defer server.Close()

	client := server.Client()
	result := &SQLResult{}
	seen := make(map[string]bool)
	var mu sync.Mutex

	baseline := checkDatabaseErrors(client, server.URL+"/", server.URL, result, "", &mu, seen, "")
	checkDatabaseErrors(client, server.URL+"/?id=1'", server.URL, result, "", &mu, seen, baseline)

	if len(result.DatabaseErrors) != 1 {
		t.Fatalf("expected 1 differential database error, got %d: %+v", len(result.DatabaseErrors), result.DatabaseErrors)
	}
	if result.DatabaseErrors[0].DatabaseType != "MySQL" {
		t.Errorf("expected database type 'MySQL', got '%s'", result.DatabaseErrors[0].DatabaseType)
	}
}

// TestCheckDatabaseErrors_PerPatternDifferential proves the baseline skip is
// per-pattern, not global: a differential postgresql leak must still be
// reported even though the response also carries a shared, baseline mysql string.
func TestCheckDatabaseErrors_PerPatternDifferential(t *testing.T) {
	const sharedMySQL = "<!-- rendered by mysql_fetch_array helper -->"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.URL.RawQuery == "id=1'" {
			_, _ = w.Write([]byte(sharedMySQL + "\npg_query() failed: ERROR: unterminated quoted string"))
			return
		}
		_, _ = w.Write([]byte(sharedMySQL + "\nWelcome"))
	}))
	defer server.Close()

	client := server.Client()
	result := &SQLResult{}
	seen := make(map[string]bool)
	var mu sync.Mutex

	baseline := checkDatabaseErrors(client, server.URL+"/", server.URL, result, "", &mu, seen, "")
	// homepage has no baseline of its own, so its mysql marker is reported once.
	if len(result.DatabaseErrors) != 1 || result.DatabaseErrors[0].DatabaseType != "MySQL" {
		t.Fatalf("expected homepage to report its own mysql marker once, got %+v", result.DatabaseErrors)
	}

	checkDatabaseErrors(client, server.URL+"/?id=1'", server.URL, result, "", &mu, seen, baseline)

	var gotPostgres, gotProbedMySQL bool
	for _, e := range result.DatabaseErrors {
		if e.URL == server.URL+"/?id=1'" && e.DatabaseType == "PostgreSQL" {
			gotPostgres = true
		}
		if e.URL == server.URL+"/?id=1'" && e.DatabaseType == "MySQL" {
			gotProbedMySQL = true
		}
	}
	if !gotPostgres {
		t.Errorf("per-pattern differential failed: postgresql leak on the probed path was suppressed (critical false negative): %+v", result.DatabaseErrors)
	}
	if gotProbedMySQL {
		t.Errorf("shared mysql pattern should have been suppressed on the probed path, but was reported: %+v", result.DatabaseErrors)
	}
}
