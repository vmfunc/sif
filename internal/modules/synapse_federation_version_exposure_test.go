package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runSynapseModule(t *testing.T, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule("../../modules/recon/synapse-federation-version-exposure.yaml")
	if err != nil {
		t.Fatalf("parse synapse module: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	res, err := modules.ExecuteHTTPModule(context.Background(), srv.URL, def, modules.Options{
		Timeout: 5 * time.Second,
		Threads: 2,
	})
	if err != nil {
		t.Fatalf("execute synapse module: %v", err)
	}
	return res
}

func synapseExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestSynapseFederationVersionExposureModule(t *testing.T) {
	// shape from element-hq/synapse FederationVersionServlet.on_GET, the
	// matrix server-server federation version endpoint (unauthenticated by spec)
	synapseBody := `{"server": {"name": "Synapse", "version": "1.99.0"}}`

	t.Run("an exposed synapse federation version endpoint is flagged and versioned", func(t *testing.T) {
		res := runSynapseModule(t, 200, synapseBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a synapse finding")
		}
		if v := synapseExtract(res, "synapse_version"); v != "1.99.0" {
			t.Errorf("synapse_version=%q, want 1.99.0", v)
		}
	})

	t.Run("a dendrite homeserver on the same federation endpoint is not flagged as synapse", func(t *testing.T) {
		// dendrite implements the same open matrix federation version api
		// with the same json shape but its own implementation name
		body := `{"server": {"name": "Dendrite", "version": "0.13.7"}}`
		if res := runSynapseModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a dendrite homeserver should not match synapse, got %d findings", len(res.Findings))
		}
	})

	t.Run("a conduit homeserver on the same federation endpoint is not flagged as synapse", func(t *testing.T) {
		body := `{"server": {"name": "Conduit", "version": "0.9.0"}}`
		if res := runSynapseModule(t, 200, body); len(res.Findings) > 0 {
			t.Errorf("a conduit homeserver should not match synapse, got %d findings", len(res.Findings))
		}
	})

	t.Run("version still extracts when json keys are reordered", func(t *testing.T) {
		// json object member order is not significant; the extractor must not
		// depend on name preceding version
		body := `{"server": {"version": "1.99.0", "name": "Synapse"}}`
		res := runSynapseModule(t, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a synapse finding on reordered keys")
		}
		if v := synapseExtract(res, "synapse_version"); v != "1.99.0" {
			t.Errorf("synapse_version=%q on reordered keys, want 1.99.0", v)
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runSynapseModule(t, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
