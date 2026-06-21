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

	"github.com/dropalldatabases/sif/internal/modules"
)

// runEnvModule runs the env exposure module end to end against a server that
// returns the same status and body for every path it requests.
func runEnvModule(t *testing.T, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/recon/env-file-exposure.yaml")
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

func envLeakedKey(res *modules.Result) string {
	for _, f := range res.Findings {
		if v := f.Extracted["leaked_key"]; v != "" {
			return v
		}
	}
	return ""
}

func TestEnvFileExposureModule(t *testing.T) {
	realEnv := "APP_NAME=Acme\nAPP_KEY=base64:Zm9vYmFy\nDB_PASSWORD=s3cr3t\nMAIL_PASSWORD=hunter2\n"
	htmlMentionsSecret := "<!DOCTYPE html>\n<html><head><title>Docs</title></head><body>" +
		"<code>APP_KEY=base64:...</code> put DB_PASSWORD= in your .env</body></html>"

	t.Run("real env body leaks", func(t *testing.T) {
		res := runEnvModule(t, 200, realEnv)
		if len(res.Findings) == 0 {
			t.Fatal("expected a finding for a real .env body")
		}
		if key := envLeakedKey(res); key != "APP_KEY" {
			t.Errorf("leaked_key=%q, want APP_KEY", key)
		}
	})

	t.Run("html page mentioning a key is not a leak", func(t *testing.T) {
		if res := runEnvModule(t, 200, htmlMentionsSecret); len(res.Findings) > 0 {
			t.Errorf("html page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("secrets behind a 404 are not a leak", func(t *testing.T) {
		if res := runEnvModule(t, 404, realEnv); len(res.Findings) > 0 {
			t.Errorf("404 should not match, got %d findings", len(res.Findings))
		}
	})
}
