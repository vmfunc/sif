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

func runBuildCredModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func buildCredExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestBuildToolCredentialExposureModules(t *testing.T) {
	const maven = "../../modules/recon/maven-settings-exposure.yaml"
	const gradle = "../../modules/recon/gradle-properties-exposure.yaml"
	const nuget = "../../modules/recon/nuget-config-exposure.yaml"

	mavenSettings := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
		"<settings xmlns=\"http://maven.apache.org/SETTINGS/1.0.0\">\n" +
		"  <servers>\n    <server>\n      <id>nexus-releases</id>\n" +
		"      <username>deploy</username>\n      <password>S3cretDeployPass</password>\n" +
		"    </server>\n  </servers>\n</settings>\n"

	gradleProps := "org.gradle.jvmargs=-Xmx2g\nossrhUsername=deployer\n" +
		"ossrhPassword=mySonatypeSecret\nsigning.password=mySigningSecret\n"

	nugetConfig := "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n" +
		"  <packageSourceCredentials>\n    <MyFeed>\n" +
		"      <add key=\"Username\" value=\"deploy\" />\n" +
		"      <add key=\"ClearTextPassword\" value=\"S3cretFeedPass\" />\n" +
		"    </MyFeed>\n  </packageSourceCredentials>\n</configuration>\n"

	t.Run("an exposed maven settings leaks the server username", func(t *testing.T) {
		res := runBuildCredModule(t, maven, 200, mavenSettings)
		if len(res.Findings) == 0 {
			t.Fatal("expected a maven finding")
		}
		if v := buildCredExtract(res, "maven_username"); v != "deploy" {
			t.Errorf("maven_username=%q, want deploy", v)
		}
	})

	t.Run("an exposed gradle properties leaks the secret property", func(t *testing.T) {
		res := runBuildCredModule(t, gradle, 200, gradleProps)
		if len(res.Findings) == 0 {
			t.Fatal("expected a gradle finding")
		}
		if v := buildCredExtract(res, "gradle_secret_property"); v != "ossrhPassword" {
			t.Errorf("gradle_secret_property=%q, want ossrhPassword", v)
		}
	})

	t.Run("an exposed nuget config leaks the feed username", func(t *testing.T) {
		res := runBuildCredModule(t, nuget, 200, nugetConfig)
		if len(res.Findings) == 0 {
			t.Fatal("expected a nuget finding")
		}
		if v := buildCredExtract(res, "nuget_username"); v != "deploy" {
			t.Errorf("nuget_username=%q, want deploy", v)
		}
	})

	t.Run("a maven settings with mirrors but no password is not flagged", func(t *testing.T) {
		body := "<settings>\n  <mirrors>\n    <mirror>\n      <id>central</id>\n" +
			"      <url>https://repo.example.com/maven2</url>\n    </mirror>\n  </mirrors>\n</settings>\n"
		if res := runBuildCredModule(t, maven, 200, body); len(res.Findings) > 0 {
			t.Errorf("a settings without a password should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page demonstrating a maven settings is not a leak", func(t *testing.T) {
		body := "<!DOCTYPE html><html><body><pre><settings><server><password>x</password></server></settings></pre></body></html>"
		if res := runBuildCredModule(t, maven, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html maven tutorial should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a gradle properties with no credential property is not flagged", func(t *testing.T) {
		body := "org.gradle.jvmargs=-Xmx2g\nversion=1.0.0\norg.gradle.daemon=true\n"
		if res := runBuildCredModule(t, gradle, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non credential properties file should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a comment naming a password is not a credential property", func(t *testing.T) {
		body := "# set your password=here before building\norg.gradle.daemon=true\n"
		if res := runBuildCredModule(t, gradle, 200, body); len(res.Findings) > 0 {
			t.Errorf("a comment line should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an empty password property is not flagged", func(t *testing.T) {
		body := "signing.password=\nsigning.keyId=24875D73\n"
		if res := runBuildCredModule(t, gradle, 200, body); len(res.Findings) > 0 {
			t.Errorf("an empty value should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page demonstrating a gradle property is not a leak", func(t *testing.T) {
		body := "<!DOCTYPE html>\n<html><body><pre>\nossrhPassword=mySonatypeSecret\n</pre></body></html>\n"
		if res := runBuildCredModule(t, gradle, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html gradle tutorial should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a nuget config without a credentials section is not flagged", func(t *testing.T) {
		body := "<configuration>\n  <packageSources>\n" +
			"    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n" +
			"  </packageSources>\n</configuration>\n"
		if res := runBuildCredModule(t, nuget, 200, body); len(res.Findings) > 0 {
			t.Errorf("a config without credentials should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a nuget credentials section without a password is not flagged", func(t *testing.T) {
		body := "<configuration>\n  <packageSourceCredentials>\n    <MyFeed>\n" +
			"      <add key=\"Username\" value=\"deploy\" />\n" +
			"    </MyFeed>\n  </packageSourceCredentials>\n</configuration>\n"
		if res := runBuildCredModule(t, nuget, 200, body); len(res.Findings) > 0 {
			t.Errorf("a credentials section without a password should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an appsettings password is not a nuget feed credential", func(t *testing.T) {
		body := "<configuration>\n  <appSettings>\n" +
			"    <add key=\"Password\" value=\"appsecret\" />\n" +
			"  </appSettings>\n</configuration>\n"
		if res := runBuildCredModule(t, nuget, 200, body); len(res.Findings) > 0 {
			t.Errorf("an appsettings password should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page demonstrating a nuget config is not a leak", func(t *testing.T) {
		body := "<!DOCTYPE html><html><body><pre><packageSourceCredentials><add key=\"ClearTextPassword\" value=\"x\" /></packageSourceCredentials></pre></body></html>"
		if res := runBuildCredModule(t, nuget, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html nuget tutorial should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{maven, gradle, nuget} {
			if res := runBuildCredModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{maven, gradle, nuget} {
			if res := runBuildCredModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
