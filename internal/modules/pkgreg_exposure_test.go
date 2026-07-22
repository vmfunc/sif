package modules_test

import "testing"

// these tests reuse runRegistryModule/registryExtract from registry_exposure_test.go.

func TestPackageRegistryExposureModules(t *testing.T) {
	const chartmuseum = "../../modules/recon/chartmuseum-index-exposure.yaml"
	const verdaccio = "../../modules/recon/verdaccio-packages-exposure.yaml"

	chartIndex := `apiVersion: v1
entries:
  mychart:
  - apiVersion: v2
    appVersion: "1.0.0"
    created: "2026-01-01T00:00:00.000000000Z"
    description: a helm chart
    digest: a1b2c3d4e5f6
    name: mychart
    urls:
    - charts/mychart-0.1.0.tgz
    version: 0.1.0
generated: "2026-01-01T00:00:00.000000000Z"
serverInfo: {}
`

	verdaccioBody := `[{"name":"my-internal-pkg","version":"1.2.3","description":"internal tool"}]`
	verdaccioJSONHeader := map[string]string{"Content-Type": "application/json"}

	t.Run("an exposed chartmuseum index is flagged and the generated timestamp is extracted", func(t *testing.T) {
		res := runRegistryModule(t, chartmuseum, 200, nil, chartIndex)
		if len(res.Findings) == 0 {
			t.Fatal("expected a chartmuseum finding")
		}
		if v := registryExtract(res, "chartmuseum_generated"); v != "2026-01-01T00:00:00.000000000Z" {
			t.Errorf("chartmuseum_generated=%q, want 2026-01-01T00:00:00.000000000Z", v)
		}
	})

	t.Run("a stock helm repo index without serverInfo is not flagged", func(t *testing.T) {
		stockIndex := `apiVersion: v1
entries:
  mychart:
  - name: mychart
    version: 0.1.0
generated: "2026-01-01T00:00:00.000000000Z"
`
		if res := runRegistryModule(t, chartmuseum, 200, nil, stockIndex); len(res.Findings) > 0 {
			t.Errorf("a stock helm index (no serverInfo) should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a chartmuseum instance behind auth returning a 401 is not flagged", func(t *testing.T) {
		if res := runRegistryModule(t, chartmuseum, 401, nil, ""); len(res.Findings) > 0 {
			t.Errorf("a 401 should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html error page mentioning chartmuseum is not flagged", func(t *testing.T) {
		htmlBody := `<!DOCTYPE html><html><head><title>404</title></head><body>apiVersion entries: serverInfo not found</body></html>`
		if res := runRegistryModule(t, chartmuseum, 200, nil, htmlBody); len(res.Findings) > 0 {
			t.Errorf("an html page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an exposed verdaccio package list is flagged and the package name is extracted", func(t *testing.T) {
		res := runRegistryModule(t, verdaccio, 200, verdaccioJSONHeader, verdaccioBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a verdaccio finding")
		}
		if v := registryExtract(res, "verdaccio_package"); v != "my-internal-pkg" {
			t.Errorf("verdaccio_package=%q, want my-internal-pkg", v)
		}
	})

	t.Run("an empty verdaccio package list still fires since the enumeration endpoint is open", func(t *testing.T) {
		res := runRegistryModule(t, verdaccio, 200, verdaccioJSONHeader, "[]")
		if len(res.Findings) == 0 {
			t.Error("expected a finding for an empty but reachable verdaccio packages endpoint")
		}
	})

	t.Run("a json array without the verdaccio json content-type header is not flagged", func(t *testing.T) {
		if res := runRegistryModule(t, verdaccio, 200, nil, verdaccioBody); len(res.Findings) > 0 {
			t.Errorf("a missing json content-type should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a verdaccio login-gated response is not flagged", func(t *testing.T) {
		if res := runRegistryModule(t, verdaccio, 401, verdaccioJSONHeader, `{"error":"not authorized"}`); len(res.Findings) > 0 {
			t.Errorf("a 401 should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an spa fallback html page served for the verdaccio path is not flagged", func(t *testing.T) {
		htmlBody := `<!DOCTYPE html><html><head><title>Verdaccio</title></head><body>[app root]</body></html>`
		htmlHeader := map[string]string{"Content-Type": "text/html"}
		if res := runRegistryModule(t, verdaccio, 200, htmlHeader, htmlBody); len(res.Findings) > 0 {
			t.Errorf("an html fallback page should not match, got %d findings", len(res.Findings))
		}
	})
}
