package modules_test

import "testing"

// laravel-telescope-exposure fires only when the dashboard actually renders: a
// 200 carrying both the Telescope title and the Vue mount id. A 403-gated
// install, a soft-404 that reflects the word, and an unrelated "telescope" page
// must all stay silent.
func TestLaravelTelescopeExposureModule(t *testing.T) {
	const telescope = "../../modules/recon/laravel-telescope-exposure.yaml"

	dashboard := `<!DOCTYPE html><html><head><title>Telescope - Acme</title></head>` +
		`<body><div id="telescope" v-cloak></div></body></html>`

	t.Run("an exposed dashboard is flagged and the app name extracted", func(t *testing.T) {
		res := runDebugModule(t, telescope, 200, dashboard)
		if len(res.Findings) == 0 {
			t.Fatal("expected a telescope finding")
		}
		if v := debugExtract(res, "app_name"); v != "Acme" {
			t.Errorf("app_name=%q, want Acme", v)
		}
	})

	t.Run("a dashboard without a configured app name still fires", func(t *testing.T) {
		body := `<!DOCTYPE html><html><head><title>Telescope</title></head>` +
			`<body><div id="telescope" v-cloak></div></body></html>`
		if res := runDebugModule(t, telescope, 200, body); len(res.Findings) == 0 {
			t.Fatal("expected a telescope finding without an app name")
		}
	})

	t.Run("a gated install returning 403 is silent", func(t *testing.T) {
		if res := runDebugModule(t, telescope, 403, dashboard); len(res.Findings) > 0 {
			t.Errorf("403-gated telescope should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an unrelated telescope page without the vue mount is silent", func(t *testing.T) {
		body := `<html><head><title>Telescope Reviews 2026</title></head>` +
			`<body><ul id="telescope-list"></ul></body></html>`
		if res := runDebugModule(t, telescope, 200, body); len(res.Findings) > 0 {
			t.Errorf("astronomy page should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic soft-404 shell is silent", func(t *testing.T) {
		body := `<html><head><title>404 Not Found</title></head><body>not found</body></html>`
		if res := runDebugModule(t, telescope, 200, body); len(res.Findings) > 0 {
			t.Errorf("soft-404 should not match, got %d findings", len(res.Findings))
		}
	})
}
