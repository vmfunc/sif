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

package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

// runBackupFilesModule runs the backup-files module end to end against a server
// that returns the same status and body for every path it requests.
func runBackupFilesModule(t *testing.T, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/recon/backup-files.yaml")
	if err != nil {
		t.Fatalf("parse: %v", err)
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
		t.Fatalf("execute: %v", err)
	}
	return res
}

func TestBackupFilesExposureModule(t *testing.T) {
	// a cms dump carries markup in post_content and postmeta, which is what the
	// html guard has to tolerate.
	wordpressDump := "-- MySQL dump 10.13\n" +
		"CREATE TABLE `wp_posts` (\n  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT\n);\n" +
		"INSERT INTO `wp_posts` VALUES (1,'<title>Hello world</title>'," +
		"'<body class=\"home\"><h1>Welcome</h1></body>');\n" +
		"INSERT INTO `wp_postmeta` VALUES (7,1,'_elementor_data'," +
		"'a:1:{s:4:\"html\";s:32:\"<!doctype html><html>saved</html>\";}');\n"

	// the soft-404 the guard was added for: the site's own shell, served 200.
	softFourOhFour := "<!DOCTYPE html>\n<html><head><title>Not found</title></head>\n" +
		"<body><p>Set your SECRET_KEY and APP_KEY before deploying.</p></body></html>\n"

	// a plain .env backup, no markup anywhere.
	envBackup := "APP_KEY=base64:Zm9vYmFy\nDB_PASSWORD=s3cr3t\n"

	t.Run("a wordpress sql dump carrying html in post content is flagged", func(t *testing.T) {
		if res := runBackupFilesModule(t, 200, wordpressDump); len(res.Findings) == 0 {
			t.Error("a real cms dump was suppressed by the html guard, this is the exact file the module is for")
		}
	})

	t.Run("a plain env backup is flagged", func(t *testing.T) {
		if res := runBackupFilesModule(t, 200, envBackup); len(res.Findings) == 0 {
			t.Error("expected a finding for a plain .env backup")
		}
	})

	t.Run("an html soft-404 shell mentioning the tokens is not flagged", func(t *testing.T) {
		if res := runBackupFilesModule(t, 200, softFourOhFour); len(res.Findings) > 0 {
			t.Errorf("html soft-404 shell should be suppressed, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runBackupFilesModule(t, 404, envBackup); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
