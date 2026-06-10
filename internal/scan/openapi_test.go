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

// a minimal openapi 3 doc with two paths/three operations, no security at all -
// every operation is unauthenticated.
const openapiJSONUnauth = `{
  "openapi": "3.0.1",
  "info": {"title": "Test API", "version": "1.0"},
  "paths": {
    "/users": {
      "get": {"summary": "list"},
      "post": {"summary": "create"}
    },
    "/admin": {
      "delete": {"summary": "nuke"}
    }
  }
}`

// same doc but with a global security requirement, so nothing is flagged unauth.
const openapiJSONSecured = `{
  "openapi": "3.0.1",
  "info": {"title": "Secured API", "version": "1.0"},
  "security": [{"bearerAuth": []}],
  "paths": {
    "/users": {"get": {"summary": "list"}}
  }
}`

// a yaml swagger 2.0 doc, to exercise the yaml parse fallback.
const openapiYAML = `swagger: "2.0"
info:
  title: YAML API
  version: "2.0"
paths:
  /ping:
    get:
      summary: health
`

// hasEndpoint reports whether the result enumerated the given path+method.
func hasEndpoint(r *OpenAPIResult, path, method string) (OpenAPIEndpoint, bool) {
	for i := 0; i < len(r.Endpoints); i++ {
		if r.Endpoints[i].Path == path && r.Endpoints[i].Method == method {
			return r.Endpoints[i], true
		}
	}
	return OpenAPIEndpoint{}, false
}

func TestOpenAPI_EnumeratesEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(openapiJSONUnauth))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result, err := OpenAPI(srv.URL, 5*time.Second, 4, "")
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if result == nil {
		t.Fatal("expected an openapi result, got nil")
	}
	if len(result.Endpoints) != 3 {
		t.Fatalf("expected 3 enumerated endpoints, got %d: %+v", len(result.Endpoints), result.Endpoints)
	}

	for _, want := range []struct{ path, method string }{
		{"/users", http.MethodGet},
		{"/users", http.MethodPost},
		{"/admin", http.MethodDelete},
	} {
		ep, ok := hasEndpoint(result, want.path, want.method)
		if !ok {
			t.Errorf("missing endpoint %s %s", want.method, want.path)
			continue
		}
		if !ep.Unauth {
			t.Errorf("expected %s %s to be flagged unauthenticated", want.method, want.path)
		}
	}

	// no security anywhere -> high exposure.
	if result.Severity != openapiSevHigh {
		t.Errorf("expected high severity for fully-unauth spec, got %q", result.Severity)
	}
	if result.Title != "Test API" {
		t.Errorf("expected title 'Test API', got %q", result.Title)
	}
}

func TestOpenAPI_SecuredSpecIsMedium(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			_, _ = w.Write([]byte(openapiJSONSecured))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result, err := OpenAPI(srv.URL, 5*time.Second, 4, "")
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if result == nil {
		t.Fatal("expected a result, got nil")
	}
	ep, ok := hasEndpoint(result, "/users", http.MethodGet)
	if !ok {
		t.Fatal("expected /users GET to be enumerated")
	}
	if ep.Unauth {
		t.Errorf("global security should mark the operation authenticated, got unauth")
	}
	if result.Severity != openapiSevMedium {
		t.Errorf("expected medium severity for a secured spec, got %q", result.Severity)
	}
}

func TestOpenAPI_YAMLSpec(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v3/api-docs" {
			w.Header().Set("Content-Type", "application/yaml")
			_, _ = w.Write([]byte(openapiYAML))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result, err := OpenAPI(srv.URL, 5*time.Second, 4, "")
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if result == nil {
		t.Fatal("expected a yaml-parsed result, got nil")
	}
	if _, ok := hasEndpoint(result, "/ping", http.MethodGet); !ok {
		t.Errorf("expected /ping GET from yaml spec, got %+v", result.Endpoints)
	}
}

// TestOpenAPI_NoSpecExposed confirms a server with no spec at any candidate path
// produces no result.
func TestOpenAPI_NoSpecExposed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result, err := OpenAPI(srv.URL, 5*time.Second, 4, "")
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result when no spec exposed, got %+v", result)
	}
}

// TestOpenAPI_RejectsUnrelatedJSON makes sure a plain json document served at a
// candidate path (no openapi/swagger version) is not treated as a spec.
func TestOpenAPI_RejectsUnrelatedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(`{"hello":"world"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result, err := OpenAPI(srv.URL, 5*time.Second, 4, "")
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if result != nil {
		t.Errorf("unrelated json should not be parsed as a spec, got %+v", result)
	}
}

func TestOpenAPIResult_ResultType(t *testing.T) {
	r := &OpenAPIResult{}
	if r.ResultType() != "openapi" {
		t.Errorf("expected result type 'openapi', got %q", r.ResultType())
	}
}
