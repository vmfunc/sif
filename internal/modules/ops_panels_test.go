package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

// runOpsModule runs a shipped module end to end against a server that returns
// the same status and body for every path it requests.
func runOpsModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func opsExtracted(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v, ok := f.Extracted[key]; ok {
			return v
		}
	}
	return ""
}

func TestOpsPanelModules(t *testing.T) {
	cases := []struct {
		name        string
		file        string
		status      int
		body        string
		wantFinding bool
		versionKey  string
		versionVal  string
	}{
		{
			name: "portainer status api", file: "../../modules/info/portainer-panel.yaml", status: 200,
			body:        `{"Edition":"CE","Version":"2.19.4","InstanceID":"a1b2c3"}`,
			wantFinding: true, versionKey: "portainer_version", versionVal: "2.19.4",
		},
		{
			name: "portainer version-only json is not a match", file: "../../modules/info/portainer-panel.yaml", status: 200,
			body: `{"Version":"1.0.0"}`, wantFinding: false,
		},
		{
			name: "portainer real body behind a 404 is not a match", file: "../../modules/info/portainer-panel.yaml", status: 404,
			body: `{"Edition":"CE","Version":"2.19.4","InstanceID":"a1b2c3"}`, wantFinding: false,
		},
		{
			name: "traefik version api", file: "../../modules/info/traefik-panel.yaml", status: 200,
			body:        `{"Version":"2.10.4","Codename":"saintnectaire","startDate":"2024-01-01T00:00:00Z"}`,
			wantFinding: true, versionKey: "traefik_version", versionVal: "2.10.4",
		},
		{
			name: "traefik without codename is not a match", file: "../../modules/info/traefik-panel.yaml", status: 200,
			body: `{"Version":"2.10.4"}`, wantFinding: false,
		},
		{
			name: "keycloak realm endpoint", file: "../../modules/info/keycloak-panel.yaml", status: 200,
			body:        `{"realm":"master","public_key":"MIIBIjAN","token-service":"https://h/realms/master/protocol/openid-connect","account-service":"https://h/realms/master/account"}`,
			wantFinding: true, versionKey: "keycloak_realm", versionVal: "master",
		},
		{
			name: "keycloak partial realm json is not a match", file: "../../modules/info/keycloak-panel.yaml", status: 200,
			body: `{"realm":"master","public_key":"MIIBIjAN"}`, wantFinding: false,
		},
		{
			name: "rabbitmq management ui", file: "../../modules/info/rabbitmq-panel.yaml", status: 200,
			body:        `<!DOCTYPE html><html><head><title>RabbitMQ Management</title></head><body><img src="img/rabbitmqlogo.svg"></body></html>`,
			wantFinding: true,
		},
		{
			name: "rabbitmq unrelated page is not a match", file: "../../modules/info/rabbitmq-panel.yaml", status: 200,
			body: `<html><body>nothing to see</body></html>`, wantFinding: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runOpsModule(t, tc.file, tc.status, tc.body)
			got := len(res.Findings) > 0
			if got != tc.wantFinding {
				t.Fatalf("findings=%d, want match=%v", len(res.Findings), tc.wantFinding)
			}
			if tc.versionKey != "" {
				if v := opsExtracted(res, tc.versionKey); v != tc.versionVal {
					t.Errorf("extracted[%q]=%q, want %q", tc.versionKey, v, tc.versionVal)
				}
			}
		})
	}
}
