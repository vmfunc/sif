package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runIntrospectionModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func introspectionExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestNodeInspectorExposureModule(t *testing.T) {
	const node = "../../modules/recon/node-inspector-exposure.yaml"

	const openInspector = `[ {
  "description": "node.js instance",
  "devtoolsFrontendUrl": "devtools://devtools/bundled/js_app.html?ws=127.0.0.1:9229/9b0e",
  "id": "9b0e",
  "title": "node[12345]",
  "type": "node",
  "url": "file:///app/server.js",
  "webSocketDebuggerUrl": "ws://127.0.0.1:9229/9b0e"
} ]`

	t.Run("an open inspector list fires and yields the ws debugger url", func(t *testing.T) {
		res := runIntrospectionModule(t, node, 200, openInspector)
		if len(res.Findings) == 0 {
			t.Fatal("expected a node inspector finding")
		}
		if v := introspectionExtract(res, "ws_debugger_url"); v != "ws://127.0.0.1:9229/9b0e" {
			t.Errorf("ws_debugger_url=%q, want ws://127.0.0.1:9229/9b0e", v)
		}
		if v := introspectionExtract(res, "inspector_title"); v != "node[12345]" {
			t.Errorf("inspector_title=%q, want node[12345]", v)
		}
	})

	t.Run("prose naming the field without the ws value is not an open inspector", func(t *testing.T) {
		body := `<html><body>attach a client to the webSocketDebuggerUrl and devtoolsFrontendUrl fields</body></html>`
		if res := runIntrospectionModule(t, node, 200, body); len(res.Findings) > 0 {
			t.Errorf("a prose mention should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("the ws url alone without the devtools frontend key does not fire", func(t *testing.T) {
		body := `[{"webSocketDebuggerUrl":"ws://127.0.0.1:9229/x"}]`
		if res := runIntrospectionModule(t, node, 200, body); len(res.Findings) > 0 {
			t.Errorf("a partial marker should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runIntrospectionModule(t, node, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runIntrospectionModule(t, node, 200, "<html><body>ok</body></html>"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 should not match, got %d findings", len(res.Findings))
		}
	})
}

func TestRailsRoutesExposureModule(t *testing.T) {
	const rails = "../../modules/recon/rails-routes-exposure.yaml"

	const routesPage = `<!DOCTYPE html><html><head><title>Routes</title></head><body>
<table><thead><tr><th>Helper</th><th>HTTP Verb</th><th>Path</th><th>Controller#Action</th></tr></thead>
<tbody><tr><td>root_path</td><td>GET</td><td>/</td><td>home#index</td></tr></tbody></table>
</body></html>`

	t.Run("an exposed dev routes page fires", func(t *testing.T) {
		res := runIntrospectionModule(t, rails, 200, routesPage)
		if len(res.Findings) == 0 {
			t.Fatal("expected a rails routes finding")
		}
	})

	t.Run("prose naming controller#action without the verb header does not fire", func(t *testing.T) {
		body := `<html><body>each route maps to a Controller#Action in rails</body></html>`
		if res := runIntrospectionModule(t, rails, 200, body); len(res.Findings) > 0 {
			t.Errorf("a prose mention should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a production routing error is not a leak", func(t *testing.T) {
		body := `<html><body>ActionController::RoutingError (No route matches [GET] "/rails/info/routes")</body></html>`
		if res := runIntrospectionModule(t, rails, 404, body); len(res.Findings) > 0 {
			t.Errorf("a 404 routing error should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		if res := runIntrospectionModule(t, rails, 200, "<html><body>ok</body></html>"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 should not match, got %d findings", len(res.Findings))
		}
	})
}

func TestOpenAPISpecExposureModule(t *testing.T) {
	const openapi = "../../modules/recon/openapi-spec-exposure.yaml"

	t.Run("an openapi 3 spec fires and yields title and version", func(t *testing.T) {
		body := `{"openapi":"3.0.1","info":{"title":"Orders API","version":"1.2.0"},"paths":{"/orders":{"get":{}}}}`
		res := runIntrospectionModule(t, openapi, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an openapi finding")
		}
		if v := introspectionExtract(res, "api_title"); v != "Orders API" {
			t.Errorf("api_title=%q, want Orders API", v)
		}
		if v := introspectionExtract(res, "api_version"); v != "3.0.1" {
			t.Errorf("api_version=%q, want 3.0.1", v)
		}
	})

	t.Run("a swagger 2 spec fires", func(t *testing.T) {
		body := `{"swagger":"2.0","info":{"title":"Legacy API"},"paths":{"/v1/orders":{}}}`
		if res := runIntrospectionModule(t, openapi, 200, body); len(res.Findings) == 0 {
			t.Fatal("expected a swagger 2 finding")
		}
	})

	t.Run("a version field with no paths object does not fire", func(t *testing.T) {
		body := `{"openapi":"3.0.1"}`
		if res := runIntrospectionModule(t, openapi, 200, body); len(res.Findings) > 0 {
			t.Errorf("a version without paths should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("prose naming openapi without the version format does not fire", func(t *testing.T) {
		body := `<html><body>we publish an openapi spec with paths documented here</body></html>`
		if res := runIntrospectionModule(t, openapi, 200, body); len(res.Findings) > 0 {
			t.Errorf("a prose mention should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runIntrospectionModule(t, openapi, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
