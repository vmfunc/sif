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

package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runMetricsModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func metricsExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestMetricsExposureModules(t *testing.T) {
	const netdata = "../../modules/recon/netdata-api-exposure.yaml"
	const cadvisor = "../../modules/recon/cadvisor-api-exposure.yaml"

	netdataInfo := `{"version":"v1.44.0","uid":"6c5c8a3f","mirrored_hosts":["localhost"],` +
		`"mirrored_hosts_status":[{"guid":"6c5c8a3f","reachable":true}],"os_name":"Debian GNU/Linux",` +
		`"cores_total":"8","total_disk_space":"512000000000"}`

	cadvisorMachine := `{"num_cores":8,"num_physical_cores":4,"num_sockets":1,"cpu_frequency_khz":2904000,` +
		`"memory_capacity":16777216000,"machine_id":"a1b2c3d4e5f60718293a4b5c6d7e8f90",` +
		`"system_uuid":"4C4C4544-0042-3110-8044-B7C04F564432","boot_id":"f0e1d2c3"}`

	t.Run("an exposed netdata info endpoint is flagged and versioned", func(t *testing.T) {
		res := runMetricsModule(t, netdata, 200, netdataInfo)
		if len(res.Findings) == 0 {
			t.Fatal("expected a netdata finding")
		}
		if v := metricsExtract(res, "netdata_version"); v != "v1.44.0" {
			t.Errorf("netdata_version=%q, want v1.44.0", v)
		}
	})

	t.Run("an exposed cadvisor machine endpoint is flagged with the machine id", func(t *testing.T) {
		res := runMetricsModule(t, cadvisor, 200, cadvisorMachine)
		if len(res.Findings) == 0 {
			t.Fatal("expected a cadvisor finding")
		}
		if v := metricsExtract(res, "cadvisor_machine_id"); v != "a1b2c3d4e5f60718293a4b5c6d7e8f90" {
			t.Errorf("cadvisor_machine_id=%q, want the machine id", v)
		}
	})

	t.Run("netdata mirrored hosts without cores total is not flagged", func(t *testing.T) {
		body := `{"version":"v1.44.0","mirrored_hosts":["localhost"]}`
		if res := runMetricsModule(t, netdata, 200, body); len(res.Findings) > 0 {
			t.Errorf("mirrored hosts alone should not match netdata, got %d findings", len(res.Findings))
		}
	})

	t.Run("netdata cores total without mirrored hosts is not flagged", func(t *testing.T) {
		body := `{"version":"v1.44.0","cores_total":"8"}`
		if res := runMetricsModule(t, netdata, 200, body); len(res.Findings) > 0 {
			t.Errorf("cores total alone should not match netdata, got %d findings", len(res.Findings))
		}
	})

	t.Run("cadvisor machine id without a cpu frequency is not flagged", func(t *testing.T) {
		body := `{"machine_id":"a1b2c3d4e5f60718293a4b5c6d7e8f90","num_cores":8}`
		if res := runMetricsModule(t, cadvisor, 200, body); len(res.Findings) > 0 {
			t.Errorf("a machine id alone should not match cadvisor, got %d findings", len(res.Findings))
		}
	})

	t.Run("cadvisor cpu frequency without a machine id is not flagged", func(t *testing.T) {
		body := `{"cpu_frequency_khz":2904000,"num_cores":8}`
		if res := runMetricsModule(t, cadvisor, 200, body); len(res.Findings) > 0 {
			t.Errorf("a cpu frequency alone should not match cadvisor, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic metrics json is not netdata", func(t *testing.T) {
		body := `{"status":"ok","data":{"result":[]}}`
		if res := runMetricsModule(t, netdata, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic json should not match netdata, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{netdata, cadvisor} {
			if res := runMetricsModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{netdata, cadvisor} {
			if res := runMetricsModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
