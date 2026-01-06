/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (Celeste Hickenlooper), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

/*

   BSD 3-Clause License
   (c) 2022-2025 vmfunc, xyzeva & contributors

*/

package detectors

import (
	"math"
	"net/http"

	fw "github.com/vmfunc/sif/internal/scan/frameworks"
)

func init() {
	// Register all backend detectors
	fw.Register(&laravelDetector{})
	fw.Register(&djangoDetector{})
	fw.Register(&railsDetector{})
	fw.Register(&expressDetector{})
	fw.Register(&aspnetDetector{})
	fw.Register(&aspnetCoreDetector{})
	fw.Register(&springDetector{})
	fw.Register(&springBootDetector{})
	fw.Register(&flaskDetector{})
	fw.Register(&symfonyDetector{})
	fw.Register(&fastapiDetector{})
	fw.Register(&ginDetector{})
	fw.Register(&phoenixDetector{})
	fw.Register(&strapiDetector{})
	fw.Register(&adonisDetector{})
	fw.Register(&cakephpDetector{})
	fw.Register(&codeigniterDetector{})
}

// sigmoidConfidence converts a weighted score to a 0-1 confidence value.
func sigmoidConfidence(score float32) float32 {
	return float32(1.0 / (1.0 + math.Exp(-float64(score)*6.0)))
}

// laravelDetector detects Laravel framework.
type laravelDetector struct {
	fw.BaseDetector
}

func (d *laravelDetector) Name() string { return "Laravel" }

func (d *laravelDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "laravel_session", Weight: 0.4, HeaderOnly: true},
		{Pattern: "XSRF-TOKEN", Weight: 0.3, HeaderOnly: true},
		{Pattern: `<meta name="csrf-token"`, Weight: 0.3},
	}
}

func (d *laravelDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// djangoDetector detects Django framework.
type djangoDetector struct{}

func (d *djangoDetector) Name() string { return "Django" }

func (d *djangoDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "csrfmiddlewaretoken", Weight: 0.4, HeaderOnly: true},
		{Pattern: "csrftoken", Weight: 0.3, HeaderOnly: true},
		{Pattern: "django.contrib", Weight: 0.3},
		{Pattern: "django.core", Weight: 0.3},
		{Pattern: "__admin_media_prefix__", Weight: 0.3},
	}
}

func (d *djangoDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// railsDetector detects Ruby on Rails framework.
type railsDetector struct{}

func (d *railsDetector) Name() string { return "Ruby on Rails" }

func (d *railsDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "csrf-param", Weight: 0.4, HeaderOnly: true},
		{Pattern: "csrf-token", Weight: 0.3, HeaderOnly: true},
		{Pattern: "_rails_session", Weight: 0.3, HeaderOnly: true},
		{Pattern: "ruby-on-rails", Weight: 0.3},
		{Pattern: "rails-env", Weight: 0.3},
		{Pattern: "data-turbo", Weight: 0.2},
	}
}

func (d *railsDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// expressDetector detects Express.js framework.
type expressDetector struct{}

func (d *expressDetector) Name() string { return "Express.js" }

func (d *expressDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "Express", Weight: 0.5, HeaderOnly: true},
		{Pattern: "connect.sid", Weight: 0.3, HeaderOnly: true},
	}
}

func (d *expressDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// aspnetDetector detects ASP.NET framework.
type aspnetDetector struct{}

func (d *aspnetDetector) Name() string { return "ASP.NET" }

func (d *aspnetDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "X-AspNet-Version", Weight: 0.5, HeaderOnly: true},
		{Pattern: "X-AspNetMvc-Version", Weight: 0.5, HeaderOnly: true},
		{Pattern: "ASP.NET", Weight: 0.4, HeaderOnly: true},
		{Pattern: "__VIEWSTATE", Weight: 0.4},
		{Pattern: "__EVENTVALIDATION", Weight: 0.3},
		{Pattern: "__VIEWSTATEGENERATOR", Weight: 0.3},
		{Pattern: ".aspx", Weight: 0.2},
		{Pattern: ".ashx", Weight: 0.2},
		{Pattern: ".asmx", Weight: 0.2},
		{Pattern: "asp.net_sessionid", Weight: 0.4, HeaderOnly: true},
		{Pattern: "X-Powered-By: ASP.NET", Weight: 0.4, HeaderOnly: true},
	}
}

func (d *aspnetDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// aspnetCoreDetector detects ASP.NET Core framework.
type aspnetCoreDetector struct{}

func (d *aspnetCoreDetector) Name() string { return "ASP.NET Core" }

func (d *aspnetCoreDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: ".AspNetCore.", Weight: 0.5, HeaderOnly: true},
		{Pattern: "blazor", Weight: 0.4},
		{Pattern: "_blazor", Weight: 0.4},
		{Pattern: "dotnet", Weight: 0.2, HeaderOnly: true},
	}
}

func (d *aspnetCoreDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// springDetector detects Spring framework.
type springDetector struct{}

func (d *springDetector) Name() string { return "Spring" }

func (d *springDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "org.springframework", Weight: 0.4, HeaderOnly: true},
		{Pattern: "spring-security", Weight: 0.3, HeaderOnly: true},
		{Pattern: "JSESSIONID", Weight: 0.3, HeaderOnly: true},
		{Pattern: "X-Application-Context", Weight: 0.3, HeaderOnly: true},
	}
}

func (d *springDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// springBootDetector detects Spring Boot framework.
type springBootDetector struct{}

func (d *springBootDetector) Name() string { return "Spring Boot" }

func (d *springBootDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "spring-boot", Weight: 0.5},
		{Pattern: "actuator", Weight: 0.3},
		{Pattern: "whitelabel", Weight: 0.2},
	}
}

func (d *springBootDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// flaskDetector detects Flask framework.
type flaskDetector struct{}

func (d *flaskDetector) Name() string { return "Flask" }

func (d *flaskDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "Werkzeug", Weight: 0.4, HeaderOnly: true},
		{Pattern: "flask", Weight: 0.3, HeaderOnly: true},
		{Pattern: "jinja2", Weight: 0.3},
	}
}

func (d *flaskDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// symfonyDetector detects Symfony framework.
type symfonyDetector struct{}

func (d *symfonyDetector) Name() string { return "Symfony" }

func (d *symfonyDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "symfony", Weight: 0.4, HeaderOnly: true},
		{Pattern: "sf_", Weight: 0.3, HeaderOnly: true},
		{Pattern: "_sf2_", Weight: 0.3, HeaderOnly: true},
	}
}

func (d *symfonyDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// fastapiDetector detects FastAPI framework.
type fastapiDetector struct{}

func (d *fastapiDetector) Name() string { return "FastAPI" }

func (d *fastapiDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "fastapi", Weight: 0.4, HeaderOnly: true},
		{Pattern: "starlette", Weight: 0.3, HeaderOnly: true},
	}
}

func (d *fastapiDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// ginDetector detects Gin framework.
type ginDetector struct{}

func (d *ginDetector) Name() string { return "Gin" }

func (d *ginDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "gin-gonic", Weight: 0.4},
		{Pattern: "gin", Weight: 0.2, HeaderOnly: true},
	}
}

func (d *ginDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// phoenixDetector detects Phoenix framework.
type phoenixDetector struct{}

func (d *phoenixDetector) Name() string { return "Phoenix" }

func (d *phoenixDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "_csrf_token", Weight: 0.4, HeaderOnly: true},
		{Pattern: "phx-", Weight: 0.3},
		{Pattern: "phoenix", Weight: 0.2},
	}
}

func (d *phoenixDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// strapiDetector detects Strapi framework.
type strapiDetector struct{}

func (d *strapiDetector) Name() string { return "Strapi" }

func (d *strapiDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "strapi", Weight: 0.4},
		{Pattern: "/api/", Weight: 0.2},
	}
}

func (d *strapiDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// adonisDetector detects AdonisJS framework.
type adonisDetector struct{}

func (d *adonisDetector) Name() string { return "AdonisJS" }

func (d *adonisDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "adonis", Weight: 0.4},
		{Pattern: "_csrf", Weight: 0.2, HeaderOnly: true},
	}
}

func (d *adonisDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// cakephpDetector detects CakePHP framework.
type cakephpDetector struct{}

func (d *cakephpDetector) Name() string { return "CakePHP" }

func (d *cakephpDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "cakephp", Weight: 0.4},
		{Pattern: "cake", Weight: 0.2},
	}
}

func (d *cakephpDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// codeigniterDetector detects CodeIgniter framework.
type codeigniterDetector struct{}

func (d *codeigniterDetector) Name() string { return "CodeIgniter" }

func (d *codeigniterDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "codeigniter", Weight: 0.4},
		{Pattern: "ci_session", Weight: 0.4, HeaderOnly: true},
	}
}

func (d *codeigniterDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}
