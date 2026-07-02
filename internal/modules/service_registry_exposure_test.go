package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

const eurekaAppsXML = `<applications><versions__delta>1</versions__delta>` +
	`<apps__hashcode>UP_5_</apps__hashcode><application><name>PAYMENT-SERVICE</name>` +
	`<instance><instanceId>10.0.0.5:payment-service:8443</instanceId>` +
	`<hostName>payment-1.svc.internal</hostName><app>PAYMENT-SERVICE</app>` +
	`<ipAddr>10.0.0.5</ipAddr><status>UP</status><port enabled="true">8443</port>` +
	`<vipAddress>payment-service</vipAddress></instance></application></applications>`

const eurekaAppsJSON = `{"applications":{"versions__delta":"1","apps__hashcode":"UP_5_",` +
	`"application":[{"name":"PAYMENT-SERVICE","instance":[{"instanceId":"p1",` +
	`"hostName":"payment-1.svc.internal","ipAddr":"10.0.0.5","status":"UP",` +
	`"vipAddress":"payment-service"}]}]}}`

const sbaInstancesJSON = `[{"id":"a1b2c3","version":12,"registration":{"name":"order-service",` +
	`"managementUrl":"http://order-1.internal:8080/actuator",` +
	`"healthUrl":"http://order-1.internal:8080/actuator/health",` +
	`"serviceUrl":"http://order-1.internal:8080/","source":"http-api","metadata":{}},` +
	`"registered":true,"statusInfo":{"status":"UP","timestamp":"2026-06-25T20:00:00Z","details":{}},` +
	`"buildVersion":"1.0.0","tags":{}}]`

func runServiceRegistryModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func svcRegExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestServiceRegistryExposureModules(t *testing.T) {
	const eureka = "../../modules/recon/eureka-registry-exposure.yaml"
	const sba = "../../modules/recon/spring-boot-admin-exposure.yaml"

	t.Run("an open eureka registry (xml) is flagged with the instance ip", func(t *testing.T) {
		res := runServiceRegistryModule(t, eureka, 200, eurekaAppsXML)
		if len(res.Findings) == 0 {
			t.Fatal("expected a eureka finding")
		}
		if v := svcRegExtract(res, "eureka_instance_ip"); v != "10.0.0.5" {
			t.Errorf("eureka_instance_ip=%q, want 10.0.0.5", v)
		}
	})

	t.Run("an open eureka registry (json) is also flagged with the instance ip", func(t *testing.T) {
		res := runServiceRegistryModule(t, eureka, 200, eurekaAppsJSON)
		if len(res.Findings) == 0 {
			t.Fatal("expected a eureka finding for the json form")
		}
		if v := svcRegExtract(res, "eureka_instance_ip"); v != "10.0.0.5" {
			t.Errorf("eureka_instance_ip=%q, want 10.0.0.5", v)
		}
	})

	t.Run("an envelope without apps__hashcode is not flagged", func(t *testing.T) {
		body := `<applications><versions__delta>1</versions__delta></applications>`
		if res := runServiceRegistryModule(t, eureka, 200, body); len(res.Findings) > 0 {
			t.Errorf("an apps__hashcode-less envelope should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a page that merely mentions applications is not flagged", func(t *testing.T) {
		body := `<html><body>Our applications support multiple versions of the eureka client.</body></html>`
		if res := runServiceRegistryModule(t, eureka, 200, body); len(res.Findings) > 0 {
			t.Errorf("a prose page should not match eureka, got %d findings", len(res.Findings))
		}
	})

	t.Run("a secured eureka is not flagged", func(t *testing.T) {
		if res := runServiceRegistryModule(t, eureka, 401, "Unauthorized"); len(res.Findings) > 0 {
			t.Errorf("a 401 eureka should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a spring boot admin body does not match the eureka module", func(t *testing.T) {
		if res := runServiceRegistryModule(t, eureka, 200, sbaInstancesJSON); len(res.Findings) > 0 {
			t.Errorf("an sba body should not match eureka, got %d findings", len(res.Findings))
		}
	})

	t.Run("an open spring boot admin is flagged with the health url", func(t *testing.T) {
		res := runServiceRegistryModule(t, sba, 200, sbaInstancesJSON)
		if len(res.Findings) == 0 {
			t.Fatal("expected an sba finding")
		}
		if v := svcRegExtract(res, "sba_health_url"); v != "http://order-1.internal:8080/actuator/health" {
			t.Errorf("sba_health_url=%q, want the internal actuator health url", v)
		}
	})

	t.Run("a registration without statusInfo is not flagged", func(t *testing.T) {
		body := `[{"registration":{"name":"x","healthUrl":"http://h:8080/health"}}]`
		if res := runServiceRegistryModule(t, sba, 200, body); len(res.Findings) > 0 {
			t.Errorf("a statusInfo-less body should not match sba, got %d findings", len(res.Findings))
		}
	})

	t.Run("a secured spring boot admin is not flagged", func(t *testing.T) {
		if res := runServiceRegistryModule(t, sba, 401, `{"error":"Unauthorized"}`); len(res.Findings) > 0 {
			t.Errorf("a 401 sba should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a eureka body does not match the spring boot admin module", func(t *testing.T) {
		if res := runServiceRegistryModule(t, sba, 200, eurekaAppsJSON); len(res.Findings) > 0 {
			t.Errorf("a eureka body should not match sba, got %d findings", len(res.Findings))
		}
	})

	t.Run("plain 200 bodies are not leaks", func(t *testing.T) {
		if res := runServiceRegistryModule(t, eureka, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 should not match eureka, got %d findings", len(res.Findings))
		}
		if res := runServiceRegistryModule(t, sba, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match sba, got %d findings", len(res.Findings))
		}
	})
}
