package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runMailAdminModule(t *testing.T, file string, status int, body string) *modules.Result {
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

// real body fragments below are trimmed from postfixadmin/postfixadmin master and
// postfixadmin-3.2 public/setup.php and public/login.php + templates/index.tpl,
// fetched from raw.githubusercontent.com to anchor the markers on actual product output.

const postfixadminSetupUnconfigured = `<!DOCTYPE html><html lang="en"><head><title>Postfix Admin - Setup</title></head>
<body><h1 class="h1">Configure and Setup Postfixadmin</h1>
<p>This page helps you setup PostfixAdmin. For further help see the documentation.</p>
<li>You need to have a setup_password hash configured in a config.local.php file</li>
<form name="setuppw" method="post" class="form-horizontal" action="setup.php">
<input type="hidden" name="form" value="setuppw"/>
<label for="setup_password" class="col-sm-4">Setup password</label>
<input class="form-control" type="password" name="setup_password" minlength=5 id="setup_password" value=""/>
</form></body></html>`

const postfixadminSetupConfigured = `<!DOCTYPE html><html lang="en"><head><title>Postfix Admin - Setup</title></head>
<body><h1 class="h1">Configure and Setup Postfixadmin</h1>
<li>setup_password configured</li>
<h2 class="h2">Login with setup_password</h2>
<form name="authenticate" class="col-12" method="post">
<label for="setup_password" class="col-sm-4 control-label">Setup password</label>
<input class="form-control" type="password" name="setup_password" minlength=5 required="required" id="setup_password" value=""/>
<button class="btn btn-primary" type="submit" name="submit" value="setuppw">Login with setup_password</button>
</form></body></html>`

const postfixadminSetupOld32 = `<html><head></head><body>
<h2>Postfix Admin Setup Checker</h2>
<p>Running software:<ul><li>PHP version 8.1.2</li></ul>
<form name="setuppw" method="post" action="setup.php">
<input type="hidden" name="form" value="setuppw" />
<label for="setup_password">Setup password</label>
<input class="flat" type="password" name="setup_password" value="" />
</form>
<!-- Since version 2.3 there is no requirement to delete setup.php! -->
</body></html>`

const postfixadminLoginPage = `<!doctype html><html lang=""><head>
<title>Postfix Admin - mail.example.com</title></head>
<body class="page-login">
<a class="navbar-brand" href='main.php'><img id="login_header_logo" src="images/postbox.png" alt="Logo"/></a>
<div id="login" class="container"><div class="card card-body">
<h2 class="h2">Login</h2>
<form name="frmLogin" method="post" action="" role="form" class="form-signin">
<label for="fUsername">Username:</label>
<input class="form-control" type="text" name="fUsername" id="fUsername"/>
<label for="fPassword">Password:</label>
<input class="form-control" type="password" name="fPassword" id="fPassword"/>
<button class="btn btn-primary btn-lg" type="submit" name="submit" value="Login">Login</button>
</form></div></div>
<footer class="footer mt-auto py-3"><div class="container text-center small">
<a target="_blank" rel="noopener" href="https://github.com/postfixadmin/postfixadmin/">PostfixAdmin</a>
</div></footer></body></html>`

func TestPostfixAdminSetupExposureModule(t *testing.T) {
	const setup = "../../modules/recon/postfixadmin-setup-exposure.yaml"

	t.Run("an unconfigured setup page is flagged", func(t *testing.T) {
		res := runMailAdminModule(t, setup, 200, postfixadminSetupUnconfigured)
		if len(res.Findings) == 0 {
			t.Fatal("expected a finding on an unconfigured postfixadmin setup page")
		}
	})

	t.Run("a configured setup login page is flagged", func(t *testing.T) {
		res := runMailAdminModule(t, setup, 200, postfixadminSetupConfigured)
		if len(res.Findings) == 0 {
			t.Fatal("expected a finding on a configured postfixadmin setup page")
		}
	})

	t.Run("an old-branch (3.2 style) setup checker page is flagged", func(t *testing.T) {
		res := runMailAdminModule(t, setup, 200, postfixadminSetupOld32)
		if len(res.Findings) == 0 {
			t.Fatal("expected a finding on the older postfixadmin setup checker layout")
		}
	})

	t.Run("the postfixadmin login page (no setup_password field) is not flagged", func(t *testing.T) {
		if res := runMailAdminModule(t, setup, 200, postfixadminLoginPage); len(res.Findings) > 0 {
			t.Errorf("the login page should not match the setup module, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic admin login page is not flagged", func(t *testing.T) {
		body := `<html><body><form><input name="username"><input name="password" type="password">
<button>Log in to Admin Panel</button></form></body></html>`
		if res := runMailAdminModule(t, setup, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic admin login should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("prose mentioning postfixadmin without the setup form is not flagged", func(t *testing.T) {
		body := `<html><body><article><h1>Postfix Admin review</h1>
<p>Postfix Admin is a popular web based interface used to manage mailboxes, virtual
domains and aliases for a Postfix mail server. Many admins prefer it over other panels
and it integrates well with a setup_password (their term for the install-time secret)
described elsewhere in the docs.</p></article></body></html>`
		if res := runMailAdminModule(t, setup, 200, body); len(res.Findings) > 0 {
			t.Errorf("a prose page discussing setup_password should not match without the real form, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not flagged", func(t *testing.T) {
		if res := runMailAdminModule(t, setup, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}

func TestPostfixAdminPanelModule(t *testing.T) {
	const panel = "../../modules/info/postfixadmin-panel.yaml"

	t.Run("a real postfixadmin login page is flagged", func(t *testing.T) {
		res := runMailAdminModule(t, panel, 200, postfixadminLoginPage)
		if len(res.Findings) == 0 {
			t.Fatal("expected a finding on the postfixadmin login page")
		}
	})

	t.Run("a generic username/password login form is not flagged", func(t *testing.T) {
		body := `<html><body><form><input name="username"><input type="password" name="password">
<button>Sign in</button></form><footer>Powered by PostfixAdmin-inspired panel</footer></body></html>`
		if res := runMailAdminModule(t, panel, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic login with a bare brand mention should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a page that only links to the postfixadmin project is not flagged", func(t *testing.T) {
		body := `<html><body><p>We migrated our mail admin panel away from
<a href="https://github.com/postfixadmin/postfixadmin/">PostfixAdmin</a> last year.</p>
<form><input name="user"><input name="pass" type="password"></form></body></html>`
		if res := runMailAdminModule(t, panel, 200, body); len(res.Findings) > 0 {
			t.Errorf("a prose link without the fUsername/fPassword fields should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a 404 is not flagged", func(t *testing.T) {
		if res := runMailAdminModule(t, panel, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match, got %d findings", len(res.Findings))
		}
	})
}
