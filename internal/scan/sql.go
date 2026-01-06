/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (Celeste Hickenlooper), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package scan

import (
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	charmlog "github.com/charmbracelet/log"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
)

// SQLResult represents the results of SQL reconnaissance
type SQLResult struct {
	AdminPanels    []SQLAdminPanel    `json:"admin_panels,omitempty"`
	DatabaseErrors []SQLDatabaseError `json:"database_errors,omitempty"`
	ExposedPorts   []int              `json:"exposed_ports,omitempty"`
}

// SQLAdminPanel represents a found database admin panel
type SQLAdminPanel struct {
	URL    string `json:"url"`
	Type   string `json:"type"`
	Status int    `json:"status"`
}

// SQLDatabaseError represents a detected database error
type SQLDatabaseError struct {
	URL          string `json:"url"`
	DatabaseType string `json:"database_type"`
	ErrorPattern string `json:"error_pattern"`
}

// common database admin panel paths
var sqlAdminPaths = []struct {
	path      string
	panelType string
}{
	{"/phpmyadmin/", "phpMyAdmin"},
	{"/phpMyAdmin/", "phpMyAdmin"},
	{"/pma/", "phpMyAdmin"},
	{"/PMA/", "phpMyAdmin"},
	{"/mysql/", "phpMyAdmin"},
	{"/myadmin/", "phpMyAdmin"},
	{"/MyAdmin/", "phpMyAdmin"},
	{"/adminer/", "Adminer"},
	{"/adminer.php", "Adminer"},
	{"/pgadmin/", "pgAdmin"},
	{"/phppgadmin/", "phpPgAdmin"},
	{"/sql/", "SQL Interface"},
	{"/db/", "Database Interface"},
	{"/database/", "Database Interface"},
	{"/dbadmin/", "Database Admin"},
	{"/mysql-admin/", "MySQL Admin"},
	{"/mysqladmin/", "MySQL Admin"},
	{"/sqlmanager/", "SQL Manager"},
	{"/websql/", "WebSQL"},
	{"/sqlweb/", "SQLWeb"},
	{"/rockmongo/", "RockMongo"},
	{"/mongodb/", "MongoDB Interface"},
	{"/mongo/", "MongoDB Interface"},
	{"/redis/", "Redis Interface"},
	{"/redis-commander/", "Redis Commander"},
	{"/phpredisadmin/", "phpRedisAdmin"},
}

// database error patterns to detect database type
var databaseErrorPatterns = []struct {
	pattern      *regexp.Regexp
	databaseType string
}{
	{regexp.MustCompile(`(?i)mysql.*error`), "MySQL"},
	{regexp.MustCompile(`(?i)mysql.*syntax`), "MySQL"},
	{regexp.MustCompile(`(?i)you have an error in your sql syntax`), "MySQL"},
	{regexp.MustCompile(`(?i)warning.*mysql`), "MySQL"},
	{regexp.MustCompile(`(?i)mysql_fetch`), "MySQL"},
	{regexp.MustCompile(`(?i)mysql_num_rows`), "MySQL"},
	{regexp.MustCompile(`(?i)mysqli`), "MySQL"},
	{regexp.MustCompile(`(?i)postgresql.*error`), "PostgreSQL"},
	{regexp.MustCompile(`(?i)pg_query`), "PostgreSQL"},
	{regexp.MustCompile(`(?i)pg_exec`), "PostgreSQL"},
	{regexp.MustCompile(`(?i)psql.*error`), "PostgreSQL"},
	{regexp.MustCompile(`(?i)unterminated quoted string`), "PostgreSQL"},
	{regexp.MustCompile(`(?i)microsoft.*odbc.*sql server`), "Microsoft SQL Server"},
	{regexp.MustCompile(`(?i)mssql.*error`), "Microsoft SQL Server"},
	{regexp.MustCompile(`(?i)sql server.*error`), "Microsoft SQL Server"},
	{regexp.MustCompile(`(?i)unclosed quotation mark`), "Microsoft SQL Server"},
	{regexp.MustCompile(`(?i)sqlsrv`), "Microsoft SQL Server"},
	{regexp.MustCompile(`(?i)ora-\d{5}`), "Oracle"},
	{regexp.MustCompile(`(?i)oracle.*error`), "Oracle"},
	{regexp.MustCompile(`(?i)oci_`), "Oracle"},
	{regexp.MustCompile(`(?i)sqlite.*error`), "SQLite"},
	{regexp.MustCompile(`(?i)sqlite3`), "SQLite"},
	{regexp.MustCompile(`(?i)sqlite_`), "SQLite"},
	{regexp.MustCompile(`(?i)mongodb.*error`), "MongoDB"},
	{regexp.MustCompile(`(?i)document.*bson`), "MongoDB"},
}

// SQL performs SQL reconnaissance on the target URL
func SQL(targetURL string, timeout time.Duration, threads int, logdir string) (*SQLResult, error) {
	log := output.Module("SQL")
	log.Start()

	spin := output.NewSpinner("Scanning for SQL exposures")
	spin.Start()

	sanitizedURL := strings.Split(targetURL, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "SQL reconnaissance"); err != nil {
			spin.Stop()
			log.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

	result := &SQLResult{
		AdminPanels:    make([]SQLAdminPanel, 0, 8),
		DatabaseErrors: make([]SQLDatabaseError, 0, 8),
	}
	seenErrors := make(map[string]bool)

	var mu sync.Mutex
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// check for admin panels
	wg.Add(threads)
	adminPathsChan := make(chan int, len(sqlAdminPaths))
	for i := range sqlAdminPaths {
		adminPathsChan <- i
	}
	close(adminPathsChan)

	for t := 0; t < threads; t++ {
		go func() {
			defer wg.Done()
			for idx := range adminPathsChan {
				adminPath := sqlAdminPaths[idx]
				checkURL := strings.TrimSuffix(targetURL, "/") + adminPath.path

				resp, err := client.Get(checkURL)
				if err != nil {
					charmlog.Debugf("Error checking %s: %v", checkURL, err)
					continue
				}

				// check for successful response (not 404)
				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
					// read body to check for common admin panel indicators
					body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*100)) // limit to 100KB
					resp.Body.Close()
					if err != nil {
						continue
					}
					bodyStr := string(body)

					// check if it's actually an admin panel (not just a generic page)
					if isAdminPanel(bodyStr, adminPath.panelType) {
						mu.Lock()
						panel := SQLAdminPanel{
							URL:    checkURL,
							Type:   adminPath.panelType,
							Status: resp.StatusCode,
						}
						result.AdminPanels = append(result.AdminPanels, panel)
						mu.Unlock()

						spin.Stop()
						log.Warn("Found %s at %s (status: %d)",
							output.SeverityHigh.Render(adminPath.panelType),
							output.Highlight.Render(checkURL),
							resp.StatusCode)
						spin.Start()

						if logdir != "" {
							logger.Write(sanitizedURL, logdir, "Found "+adminPath.panelType+" at ["+checkURL+"] (status: "+strconv.Itoa(resp.StatusCode)+")\n")
						}
					}
				} else {
					resp.Body.Close()
				}
			}
		}()
	}
	wg.Wait()

	// check main URL for database errors
	checkDatabaseErrors(client, targetURL, sanitizedURL, result, logdir, &mu, seenErrors)

	// check common endpoints that might expose database errors
	errorCheckPaths := []string{
		"/?id=1'",
		"/?id=1\"",
		"/?page=1'",
		"/?q=test'",
		"/search?q=test'",
		"/login",
		"/api/",
	}

	for _, path := range errorCheckPaths {
		checkURL := strings.TrimSuffix(targetURL, "/") + path
		checkDatabaseErrors(client, checkURL, sanitizedURL, result, logdir, &mu, seenErrors)
	}

	spin.Stop()

	// summary
	totalFindings := len(result.AdminPanels) + len(result.DatabaseErrors)
	if len(result.AdminPanels) > 0 {
		log.Warn("Found %d database admin panel(s)", len(result.AdminPanels))
	}
	if len(result.DatabaseErrors) > 0 {
		log.Warn("Found %d database error disclosure(s)", len(result.DatabaseErrors))
	}

	if totalFindings == 0 {
		log.Info("No SQL exposures found")
		log.Complete(0, "found")
		return nil, nil
	}

	log.Complete(totalFindings, "found")
	return result, nil
}

func isAdminPanel(body string, panelType string) bool {
	bodyLower := strings.ToLower(body)

	switch panelType {
	case "phpMyAdmin":
		return strings.Contains(bodyLower, "phpmyadmin") ||
			strings.Contains(bodyLower, "pma_") ||
			strings.Contains(body, "phpMyAdmin")
	case "Adminer":
		return strings.Contains(bodyLower, "adminer") ||
			strings.Contains(body, "Adminer")
	case "pgAdmin":
		return strings.Contains(bodyLower, "pgadmin") ||
			strings.Contains(body, "pgAdmin")
	case "phpPgAdmin":
		return strings.Contains(bodyLower, "phppgadmin")
	case "RockMongo":
		return strings.Contains(bodyLower, "rockmongo")
	case "Redis Commander":
		return strings.Contains(bodyLower, "redis commander") ||
			strings.Contains(bodyLower, "redis-commander")
	case "phpRedisAdmin":
		return strings.Contains(bodyLower, "phpredisadmin")
	default:
		// for generic database interfaces, check for common keywords
		return strings.Contains(bodyLower, "database") ||
			strings.Contains(bodyLower, "sql") ||
			strings.Contains(bodyLower, "query") ||
			strings.Contains(bodyLower, "mysql") ||
			strings.Contains(bodyLower, "postgresql") ||
			strings.Contains(bodyLower, "mongodb")
	}
}

func checkDatabaseErrors(client *http.Client, checkURL, sanitizedURL string, result *SQLResult, logdir string, mu *sync.Mutex, seen map[string]bool) {
	resp, err := client.Get(checkURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*100))
	if err != nil {
		return
	}
	bodyStr := string(body)

	for _, pattern := range databaseErrorPatterns {
		if pattern.pattern.MatchString(bodyStr) {
			key := checkURL + "|" + pattern.databaseType
			mu.Lock()
			if seen[key] {
				mu.Unlock()
				break
			}
			seen[key] = true

			dbError := SQLDatabaseError{
				URL:          checkURL,
				DatabaseType: pattern.databaseType,
				ErrorPattern: pattern.pattern.String(),
			}
			result.DatabaseErrors = append(result.DatabaseErrors, dbError)
			mu.Unlock()

			output.Warn("Database error disclosure: %s at %s",
				output.SeverityHigh.Render(pattern.databaseType),
				output.Highlight.Render(checkURL))

			if logdir != "" {
				logger.Write(sanitizedURL, logdir, "Database error disclosure: "+pattern.databaseType+" at ["+checkURL+"]\n")
			}
			break // only report one database type per URL
		}
	}
}
