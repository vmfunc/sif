package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runInfraControlplaneModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func controlplaneExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestInfraControlplaneExposureModules(t *testing.T) {
	const traefik = "../../modules/recon/traefik-api-exposure.yaml"
	const nomad = "../../modules/recon/nomad-agent-exposure.yaml"
	const portainer = "../../modules/recon/portainer-status-exposure.yaml"

	t.Run("a traefik overview is flagged with its first provider", func(t *testing.T) {
		body := `{"http":{"routers":{"total":12,"warnings":0,"errors":1},"services":{"total":8,"warnings":0,` +
			`"errors":0},"middlewares":{"total":5,"warnings":0,"errors":0}},"tcp":{"routers":{"total":0},` +
			`"services":{"total":0}},"udp":{"routers":{"total":0},"services":{"total":0}},` +
			`"features":{"tracing":"Noop","metrics":"Prometheus","accessLog":true},"providers":["Docker","File"]}`
		res := runInfraControlplaneModule(t, traefik, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a traefik finding")
		}
		if v := controlplaneExtract(res, "traefik_provider"); v != "Docker" {
			t.Errorf("traefik_provider=%q, want Docker", v)
		}
	})

	t.Run("a routing summary without features is not flagged as traefik", func(t *testing.T) {
		body := `{"http":{"routers":{"total":1}},"providers":["Docker"]}`
		if res := runInfraControlplaneModule(t, traefik, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without features should not match traefik, got %d findings", len(res.Findings))
		}
	})

	t.Run("an open nomad agent self is flagged with its version", func(t *testing.T) {
		body := `{"config":{"Region":"global","Datacenter":"dc1","BindAddr":"0.0.0.0"},` +
			`"member":{"Name":"node1.global","Addr":"10.0.0.5","Port":4648,` +
			`"Tags":{"role":"nomad","region":"global","dc":"dc1","build":"1.7.2","vsn":"1"},"Status":"alive"},` +
			`"stats":{"nomad":{"server":"true"},"runtime":{"version":"go1.21"}}}`
		res := runInfraControlplaneModule(t, nomad, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a nomad finding")
		}
		if v := controlplaneExtract(res, "nomad_version"); v != "1.7.2" {
			t.Errorf("nomad_version=%q, want 1.7.2", v)
		}
	})

	t.Run("an acl-enabled nomad returns 403 and is not flagged", func(t *testing.T) {
		if res := runInfraControlplaneModule(t, nomad, 403, `{"errors":["Permission denied"]}`); len(res.Findings) > 0 {
			t.Errorf("a 403 from an acl-enabled nomad should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a config+stats body without member is not flagged as nomad", func(t *testing.T) {
		body := `{"config":{"a":1},"stats":{"b":2}}`
		if res := runInfraControlplaneModule(t, nomad, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without member should not match nomad, got %d findings", len(res.Findings))
		}
	})

	t.Run("a portainer status is flagged with its instance id", func(t *testing.T) {
		body := `{"Version":"2.19.4","InstanceID":"299ab403-70a8-4c05-92f7-bf7a994d50df"}`
		res := runInfraControlplaneModule(t, portainer, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a portainer finding")
		}
		if v := controlplaneExtract(res, "portainer_instance_id"); v != "299ab403-70a8-4c05-92f7-bf7a994d50df" {
			t.Errorf("portainer_instance_id=%q, want the uuid", v)
		}
	})

	t.Run("a bare version body is not flagged as portainer", func(t *testing.T) {
		if res := runInfraControlplaneModule(t, portainer, 200, `{"Version":"2.19.4"}`); len(res.Findings) > 0 {
			t.Errorf("a bare version should not match portainer, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{traefik, nomad, portainer} {
			if res := runInfraControlplaneModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{traefik, nomad, portainer} {
			if res := runInfraControlplaneModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
