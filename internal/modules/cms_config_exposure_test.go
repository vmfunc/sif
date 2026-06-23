package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runCMSCfgModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func cmsCfgExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestCMSConfigExposureModules(t *testing.T) {
	const joomla = "../../modules/recon/joomla-config-exposure.yaml"
	const drupal = "../../modules/recon/drupal-config-exposure.yaml"
	const magento = "../../modules/recon/magento-config-exposure.yaml"

	joomlaConfig := "<?php\nclass JConfig {\n\tpublic $offline = '0';\n" +
		"\tpublic $host = 'localhost';\n\tpublic $user = 'joomla_user';\n" +
		"\tpublic $password = 'S3cretJoomlaPass';\n\tpublic $db = 'joomla_db';\n" +
		"\tpublic $dbprefix = 'jos_';\n\tpublic $secret = 'AbCdEfGhIjKlMnOp';\n}\n"

	drupalConfig := "<?php\n$databases['default']['default'] = array (\n" +
		"  'database' => 'drupal_db',\n  'username' => 'drupal_user',\n" +
		"  'password' => 'S3cretDrupalPass',\n  'host' => 'localhost',\n" +
		"  'driver' => 'mysql',\n);\n$settings['hash_salt'] = 'longrandomhashsalt';\n"

	magentoConfig := "<?php\nreturn [\n  'backend' => ['frontName' => 'admin_x7y'],\n" +
		"  'crypt' => ['key' => 'a1b2c3d4e5f6g7h8'],\n  'db' => [\n" +
		"    'connection' => ['default' => [\n      'host' => 'localhost',\n" +
		"      'dbname' => 'magento',\n      'username' => 'magento_user',\n" +
		"      'password' => 'S3cretMagentoPass',\n    ]],\n  ],\n  'MAGE_MODE' => 'production',\n];\n"

	t.Run("an exposed joomla configuration leaks the password", func(t *testing.T) {
		res := runCMSCfgModule(t, joomla, 200, joomlaConfig)
		if len(res.Findings) == 0 {
			t.Fatal("expected a joomla finding")
		}
		if v := cmsCfgExtract(res, "joomla_password"); v != "S3cretJoomlaPass" {
			t.Errorf("joomla_password=%q, want S3cretJoomlaPass", v)
		}
	})

	t.Run("an exposed drupal settings leaks the password", func(t *testing.T) {
		res := runCMSCfgModule(t, drupal, 200, drupalConfig)
		if len(res.Findings) == 0 {
			t.Fatal("expected a drupal finding")
		}
		if v := cmsCfgExtract(res, "drupal_password"); v != "S3cretDrupalPass" {
			t.Errorf("drupal_password=%q, want S3cretDrupalPass", v)
		}
	})

	t.Run("an exposed magento env leaks the crypt key", func(t *testing.T) {
		res := runCMSCfgModule(t, magento, 200, magentoConfig)
		if len(res.Findings) == 0 {
			t.Fatal("expected a magento finding")
		}
		if v := cmsCfgExtract(res, "magento_crypt_key"); v != "a1b2c3d4e5f6g7h8" {
			t.Errorf("magento_crypt_key=%q, want a1b2c3d4e5f6g7h8", v)
		}
	})

	t.Run("a joomla config missing the password is not flagged", func(t *testing.T) {
		body := "<?php\nclass JConfig {\n\tpublic $host = 'localhost';\n" +
			"\tpublic $db = 'joomla_db';\n\tpublic $dbprefix = 'jos_';\n}\n"
		if res := runCMSCfgModule(t, joomla, 200, body); len(res.Findings) > 0 {
			t.Errorf("a config without a password should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a php class with a public password but no jconfig is not joomla", func(t *testing.T) {
		body := "<?php\nclass MyAuth {\n\tpublic $password = 'changeme';\n" +
			"\tpublic $username = 'admin';\n}\n"
		if res := runCMSCfgModule(t, joomla, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic class should not match joomla, got %d findings", len(res.Findings))
		}
	})

	t.Run("a php array with a password but no databases is not drupal", func(t *testing.T) {
		body := "<?php\n$config = array('password' => 'x', 'host' => 'y');\n"
		if res := runCMSCfgModule(t, drupal, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic array should not match drupal, got %d findings", len(res.Findings))
		}
	})

	t.Run("a drupal databases array without a password is not flagged", func(t *testing.T) {
		body := "<?php\n$databases['default']['default'] = array (\n" +
			"  'database' => 'drupal_db',\n  'host' => 'localhost',\n  'driver' => 'mysql',\n);\n"
		if res := runCMSCfgModule(t, drupal, 200, body); len(res.Findings) > 0 {
			t.Errorf("a databases array without a password should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a php return array with a password but no magento markers is not flagged", func(t *testing.T) {
		body := "<?php\nreturn ['db' => ['password' => 'secret', 'host' => 'localhost']];\n"
		if res := runCMSCfgModule(t, magento, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic return array should not match magento, got %d findings", len(res.Findings))
		}
	})

	t.Run("a magento config without a credential is not flagged", func(t *testing.T) {
		body := "<?php\nreturn ['MAGE_MODE' => 'production', 'db' => ['host' => 'localhost']];\n"
		if res := runCMSCfgModule(t, magento, 200, body); len(res.Findings) > 0 {
			t.Errorf("a magento config without a credential should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page demonstrating a joomla config is not a leak", func(t *testing.T) {
		body := "<!DOCTYPE html><html><body><pre>class JConfig { public $password = 'x'; public $db = 'y'; }</pre></body></html>"
		if res := runCMSCfgModule(t, joomla, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html joomla tutorial should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a drupal settings using env indirection is not a literal password leak", func(t *testing.T) {
		body := "<?php\n$databases['default']['default'] = array (\n" +
			"  'database' => 'drupal_db',\n  'username' => 'drupal_user',\n" +
			"  'password' => getenv('DB_PASS'),\n  'host' => 'localhost',\n);\n"
		if res := runCMSCfgModule(t, drupal, 200, body); len(res.Findings) > 0 {
			t.Errorf("env indirection should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a magento env with a cloud placeholder key is not a literal leak", func(t *testing.T) {
		body := "<?php\nreturn ['crypt' => ['key' => '#env.CRYPT_KEY#'], 'MAGE_MODE' => 'production'];\n"
		if res := runCMSCfgModule(t, magento, 200, body); len(res.Findings) > 0 {
			t.Errorf("a cloud placeholder should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a magento env with a placeholder key but a literal password is flagged not mis-extracted", func(t *testing.T) {
		body := "<?php\nreturn ['crypt' => ['key' => '#env.CRYPT_KEY#'],\n" +
			"  'db' => ['connection' => ['default' => ['password' => 'RealDbPass']]],\n" +
			"  'MAGE_MODE' => 'production'];\n"
		res := runCMSCfgModule(t, magento, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a magento finding on the literal password")
		}
		if v := cmsCfgExtract(res, "magento_crypt_key"); v == "#env.CRYPT_KEY#" {
			t.Errorf("extractor surfaced the placeholder %q as the crypt key", v)
		}
	})

	t.Run("an html page demonstrating a drupal config is not a leak", func(t *testing.T) {
		body := "<!DOCTYPE html><html><body><pre>$databases['default']['default'] = array('password' => 'x');</pre></body></html>"
		if res := runCMSCfgModule(t, drupal, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html drupal tutorial should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("an html page demonstrating a magento config is not a leak", func(t *testing.T) {
		body := "<!DOCTYPE html><html><body><pre>'crypt' => ['key' => 'x'], 'MAGE_MODE' => 'production'</pre></body></html>"
		if res := runCMSCfgModule(t, magento, 200, body); len(res.Findings) > 0 {
			t.Errorf("an html magento tutorial should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{joomla, drupal, magento} {
			if res := runCMSCfgModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{joomla, drupal, magento} {
			if res := runCMSCfgModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
