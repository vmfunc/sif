package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runIloModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func iloExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestHPEIloXMLDataExposureModule(t *testing.T) {
	const ilo = "../../modules/recon/hpe-ilo-xmldata-exposure.yaml"

	t.Run("a real ilo xmldata response is flagged with serial, product and firmware", func(t *testing.T) {
		body := `<?xml version="1.0"?><RIMP><HSI><SBSN>CZC1234ABC </SBSN><SPN>ProLiant DL380 Gen10</SPN>` +
			`<UUID>31393736-3935-435A-4331-323334414243</UUID><SP>1</SP><cUUID>00000000-0000-0000-0000-000000000000</cUUID>` +
			`<VIRTUAL><STATE>Inactive</STATE><VID><BSN></BSN><cUUID></cUUID></VID></VIRTUAL></HSI>` +
			`<MP><ST>1</ST><PN>Integrated Lights-Out 5 (iLO 5)</PN><FWRI>2.44</FWRI><HWRI>ASIC: 17</HWRI>` +
			`<SN>ILO1234567890 </SN><UUID>ILO000000000000</UUID><IPM>1</IPM><SSO>0</SSO><PWRM>3.4</PWRM></MP></RIMP>`
		res := runIloModule(t, ilo, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an ilo xmldata finding")
		}
		if v := iloExtract(res, "ilo_server_serial"); v != "CZC1234ABC" {
			t.Errorf("ilo_server_serial=%q, want CZC1234ABC", v)
		}
		if v := iloExtract(res, "ilo_server_product"); v != "ProLiant DL380 Gen10" {
			t.Errorf("ilo_server_product=%q, want ProLiant DL380 Gen10", v)
		}
		if v := iloExtract(res, "ilo_firmware"); v != "2.44" {
			t.Errorf("ilo_firmware=%q, want 2.44", v)
		}
	})

	t.Run("an unrelated xml api with a generic RIMP-shaped body is not flagged", func(t *testing.T) {
		body := `<?xml version="1.0"?><RIMP><HSI><SBSN>FAKE</SBSN></HSI><MP><PN>Generic Management Card</PN></MP></RIMP>`
		if res := runIloModule(t, ilo, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non-ilo RIMP-shaped body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a page that merely mentions Integrated Lights-Out in prose is not flagged", func(t *testing.T) {
		body := `<html><body>Our support team can help configure Integrated Lights-Out on your HPE server.</body></html>`
		if res := runIloModule(t, ilo, 200, body); len(res.Findings) > 0 {
			t.Errorf("a prose mention should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		if res := runIloModule(t, ilo, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
