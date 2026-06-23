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

// a globally-secured spec mixing public opt-outs (security: [] and security: [{}])
// with operations that inherit or declare their own requirement.
const openapiJSONPublicOverride = `{
  "openapi": "3.0.1",
  "info": {"title": "Override API", "version": "1.0"},
  "security": [{"bearerAuth": []}],
  "paths": {
    "/me":       {"get": {"summary": "authed, inherits global"}},
    "/admin":    {"get": {"summary": "authed, explicit non-empty", "security": [{"bearerAuth": []}]}},
    "/login":    {"post": {"summary": "public override", "security": []}},
    "/optional": {"get": {"summary": "anonymous allowed", "security": [{}]}}
  }
}`

// a yaml spec with global auth and an operation that opts out via security: [],
// to lock the empty-vs-absent distinction on the yaml decode path too.
const openapiYAMLPublicOverride = `openapi: "3.0.1"
info:
  title: YAML Override API
  version: "1.0"
security:
  - bearerAuth: []
paths:
  /token:
    post:
      summary: public
      security: []
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

// TestOpenAPI_PublicOverridesAreUnauth checks that operations allowing anonymous
// access (security: [] or security: [{}]) are flagged unauthenticated, while ones
// that inherit the enforced global default or declare their own requirement stay authed.
func TestOpenAPI_PublicOverridesAreUnauth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			_, _ = w.Write([]byte(openapiJSONPublicOverride))
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

	for _, want := range []struct {
		path, method string
		unauth       bool
		why          string
	}{
		{"/login", http.MethodPost, true, "security: [] removes the global requirement"},
		{"/optional", http.MethodGet, true, "security: [{}] permits anonymous access"},
		{"/me", http.MethodGet, false, "inherits the enforced global requirement"},
		{"/admin", http.MethodGet, false, "declares its own non-empty requirement"},
	} {
		ep, ok := hasEndpoint(result, want.path, want.method)
		if !ok {
			t.Fatalf("expected %s %s to be enumerated", want.method, want.path)
		}
		if ep.Unauth != want.unauth {
			t.Errorf("%s %s unauth=%v, want %v (%s)", want.method, want.path, ep.Unauth, want.unauth, want.why)
		}
	}

	if result.Severity != openapiSevHigh {
		t.Errorf("an unauthenticated operation should rank the exposure high, got %q", result.Severity)
	}
}

// TestOpenAPI_YAMLPublicOverrideIsUnauth locks the empty-vs-absent distinction on
// the yaml decode path: yaml.v3 must preserve security: [] as a non-nil empty
// block, or the whole fix silently regresses on yaml specs.
func TestOpenAPI_YAMLPublicOverrideIsUnauth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v3/api-docs" {
			w.Header().Set("Content-Type", "application/yaml")
			_, _ = w.Write([]byte(openapiYAMLPublicOverride))
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
		t.Fatal("expected a yaml result, got nil")
	}
	ep, ok := hasEndpoint(result, "/token", http.MethodPost)
	if !ok {
		t.Fatal("expected /token POST to be enumerated")
	}
	if !ep.Unauth {
		t.Error("yaml security: [] should be flagged unauthenticated; yaml.v3 must keep it non-nil")
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
