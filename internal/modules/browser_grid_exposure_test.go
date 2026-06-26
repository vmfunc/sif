package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runGridModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func gridExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

const seleniumStatusBody = `{"value":{"ready":true,"message":"Selenium Grid ready.","nodes":[` +
	`{"id":"028ca108-bfc4-430e-806c-6477b6b8569e","uri":"http://10.0.0.5:5555","maxSessions":1,` +
	`"osInfo":{"arch":"amd64","name":"Linux","version":"5.15.0"},"heartbeatPeriod":60000,` +
	`"availability":"UP","version":"4.18.1 (revision b1d3319b48)","slots":[{"lastStarted":` +
	`"2024-06-01T10:00:00Z","session":null,"id":{"hostId":"028ca108","id":"fdd41c10"},` +
	`"stereotype":{"browserName":"chrome","platformName":"LINUX"}}]}]}}`

const selenoidStatusBody = `{"total":80,"used":10,"queued":0,"pending":1,"browsers":{"chrome":` +
	`{"124.0":{"user1":{"count":1,"sessions":[{"id":"abc","container":"sel-abc"}]}}},"firefox":{"125.0":{}}}}`

func TestBrowserGridExposureModules(t *testing.T) {
	const selenium = "../../modules/recon/selenium-grid-exposure.yaml"
	const selenoid = "../../modules/recon/selenoid-exposure.yaml"

	t.Run("a selenium grid status is flagged with a node version", func(t *testing.T) {
		res := runGridModule(t, selenium, 200, seleniumStatusBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a selenium finding")
		}
		if v := gridExtract(res, "selenium_version"); v != "4.18.1 (revision b1d3319b48)" {
			t.Errorf("selenium_version=%q, want the node build string", v)
		}
	})

	t.Run("a value+nodes envelope without the selenium grid message is not flagged", func(t *testing.T) {
		body := `{"value":{"ready":true,"nodes":[{"id":"n1","name":"router"}]}}`
		if res := runGridModule(t, selenium, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic value/nodes blob should not match selenium, got %d findings", len(res.Findings))
		}
	})

	t.Run("a selenoid status is flagged with the first browser", func(t *testing.T) {
		res := runGridModule(t, selenoid, 200, selenoidStatusBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a selenoid finding")
		}
		if v := gridExtract(res, "selenoid_browser"); v != "chrome" {
			t.Errorf("selenoid_browser=%q, want chrome", v)
		}
	})

	t.Run("a capacity blob without browsers is not flagged as selenoid", func(t *testing.T) {
		if res := runGridModule(t, selenoid, 200, `{"total":80,"used":10,"queued":0,"pending":1}`); len(res.Findings) > 0 {
			t.Errorf("a browserless capacity blob should not match selenoid, got %d findings", len(res.Findings))
		}
	})

	t.Run("the two grid modules do not cross-match each other", func(t *testing.T) {
		if res := runGridModule(t, selenoid, 200, seleniumStatusBody); len(res.Findings) > 0 {
			t.Errorf("selenium status should not match selenoid, got %d findings", len(res.Findings))
		}
		if res := runGridModule(t, selenium, 200, selenoidStatusBody); len(res.Findings) > 0 {
			t.Errorf("selenoid status should not match selenium, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{selenium, selenoid} {
			if res := runGridModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{selenium, selenoid} {
			if res := runGridModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
