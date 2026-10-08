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

package modules

import (
	"net/http"
	"strings"
	"testing"
)

func TestDSLCompile(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{"valid comparison", "status_code == 200", false},
		{"valid helper", `contains(body, "admin")`, false},
		{"bad syntax", "status_code ==", true},
		{"non-allowlisted side-effect helper", "wait_for(1)", true},
		{"non-allowlisted network helper", "public_ip()", true},
		{"non-allowlisted alloc helper", `repeat("A", 1000000)`, true},
		{"over-length expression", strings.Repeat("a", maxDSLExprLen+1), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := dslCompile(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("dslCompile(%q) err = %v, wantErr %v", tt.expr, err, tt.wantErr)
			}
		})
	}
}

func TestCheckMatcherDSL(t *testing.T) {
	const body = "welcome admin dashboard"
	resp := fakeResponse(t, 200, http.Header{"X-Powered-By": []string{"nginx"}})
	mc := &MatchContext{Resp: resp, Body: body}

	tests := []struct {
		name   string
		dsl    []string
		expect bool
	}{
		{"status_code true", []string{"status_code == 200"}, true},
		{"status_code false", []string{"status_code == 500"}, false},
		{"body contains", []string{`contains(body, "admin")`}, true},
		{"content_length", []string{"content_length > 5"}, true},
		{"all_headers", []string{`contains(to_lower(all_headers), "nginx")`}, true},
		{"header alias", []string{`contains(to_lower(header), "nginx")`}, true},
		{"unbound var misses", []string{"nonexistent_var == 1"}, false},
		{"non-bool result misses", []string{"len(body)"}, false},
		{"empty list false", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Matcher{Type: "dsl", DSL: tt.dsl}
			if got := checkMatcher(m, mc); got != tt.expect {
				t.Errorf("dsl %v = %v, want %v", tt.dsl, got, tt.expect)
			}
		})
	}
}

func TestCheckMatcherDSLCondition(t *testing.T) {
	const body = "hello world"
	mc := &MatchContext{Resp: fakeResponse(t, 200, nil), Body: body}
	trueExpr := "status_code == 200"
	falseExpr := "status_code == 500"

	tests := []struct {
		name      string
		condition string
		dsl       []string
		expect    bool
	}{
		{"and both true", "and", []string{trueExpr, `contains(body, "hello")`}, true},
		{"and one false", "and", []string{trueExpr, falseExpr}, false},
		{"empty defaults to and", "", []string{trueExpr, falseExpr}, false},
		{"or one true", "or", []string{falseExpr, trueExpr}, true},
		{"or none true", "or", []string{falseExpr, `contains(body, "absent")`}, false},
		{"AND case-insensitive", "AND", []string{trueExpr, falseExpr}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Matcher{Type: "dsl", Condition: tt.condition, DSL: tt.dsl}
			if got := checkMatcher(m, mc); got != tt.expect {
				t.Errorf("dsl cond %q %v = %v, want %v", tt.condition, tt.dsl, got, tt.expect)
			}
		})
	}
}

func TestCheckMatcherDSLNegative(t *testing.T) {
	mc := &MatchContext{Resp: fakeResponse(t, 200, nil), Body: "x"}
	ms := []Matcher{{Type: "dsl", DSL: []string{"status_code == 200"}, Negative: true}}
	if checkMatchers(ms, "", mc) {
		t.Error("negative dsl matcher on a matching response should yield false")
	}
}

func TestCheckMatcherDSLHost(t *testing.T) {
	// host must bind the hostname (nuclei parity), not the full requested URL,
	// so a pasted `host == "..."` expression behaves as a nuclei user expects.
	mc := &MatchContext{
		Resp: fakeResponse(t, 200, nil),
		Body: "x",
		URL:  "http://example.com/admin/panel",
	}
	if m := (&Matcher{Type: "dsl", DSL: []string{`host == "example.com"`}}); !checkMatcher(m, mc) {
		t.Error(`host should bind the hostname "example.com", got a miss`)
	}
	if m := (&Matcher{Type: "dsl", DSL: []string{`contains(host, "/admin")`}}); checkMatcher(m, mc) {
		t.Error("host must not contain the URL path")
	}
}

func TestCheckMatcherDSLURLPartVars(t *testing.T) {
	// each row pins one nuclei URL-part semantic (see dslVars); the values are
	// deliberately counterintuitive, so this is the regression guard on parity.
	mc := &MatchContext{
		Resp: fakeResponse(t, 200, nil),
		Body: "x",
		URL:  "https://sub.example.com:8443/admin/login?q=1",
	}
	rows := []struct {
		name string
		expr string
	}{
		{"Scheme", `Scheme == "https"`},
		{"Host is hostname without port", `Host == "sub.example.com"`},
		{"Hostname carries the port", `Hostname == "sub.example.com:8443"`},
		{"Port explicit", `Port == "8443"`},
		{"Path is the directory", `Path == "/admin"`},
		{"File is the last segment", `File == "login"`},
		{"BaseURL is full url, query stripped", `BaseURL == "https://sub.example.com:8443/admin/login"`},
		{"RootURL is scheme://host", `RootURL == "https://sub.example.com:8443"`},
		{"Query", `Query == "?q=1"`},
		{"FQDN", `FQDN == "sub.example.com"`},
		{"RDN", `RDN == "example.com"`},
		{"DN", `DN == "example"`},
		{"TLD", `TLD == "com"`},
		{"SD", `SD == "sub"`},
	}
	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			m := &Matcher{Type: "dsl", DSL: []string{tt.expr}}
			if !checkMatcher(m, mc) {
				t.Errorf("expr %q should match, got a miss", tt.expr)
			}
		})
	}
}

func TestCheckMatcherDSLPortDefaultsByScheme(t *testing.T) {
	// Port defaults to the scheme's well-known port when the URL omits it,
	// matching nuclei so `Port == "443"` works against a plain https target.
	cases := []struct{ url, port string }{
		{"https://example.com/", "443"},
		{"http://example.com/", "80"},
	}
	for _, c := range cases {
		mc := &MatchContext{Resp: fakeResponse(t, 200, nil), Body: "x", URL: c.url}
		m := &Matcher{Type: "dsl", DSL: []string{`Port == "` + c.port + `"`}}
		if !checkMatcher(m, mc) {
			t.Errorf("%s: Port should default to %q", c.url, c.port)
		}
	}
}

func TestCheckMatcherDSLExtractorVar(t *testing.T) {
	mc := &MatchContext{
		Resp:      fakeResponse(t, 200, nil),
		Body:      "x",
		Extracted: map[string]string{"version": "1.2.3"},
	}
	m := &Matcher{Type: "dsl", DSL: []string{`version == "1.2.3"`}}
	if !checkMatcher(m, mc) {
		t.Error("dsl matcher should see the named extractor variable")
	}
}

func TestCheckMatcherDSLEvalErrorMisses(t *testing.T) {
	mc := &MatchContext{Resp: fakeResponse(t, 200, nil), Body: "x"}
	// compiles fine, errors at eval (string vs number comparison)
	m := &Matcher{Type: "dsl", DSL: []string{`body > 5`}}
	if checkMatcher(m, mc) {
		t.Error("an expression that errors at eval must miss, not match")
	}
	// under or, a bad-eval expr followed by a valid true expr still matches
	m2 := &Matcher{Type: "dsl", Condition: "or", DSL: []string{`body > 5`, "status_code == 200"}}
	if !checkMatcher(m2, mc) {
		t.Error("or with a valid true expr after a bad-eval expr should match")
	}
}

func TestCheckMatcherDSLCompileErrorMisses(t *testing.T) {
	mc := &MatchContext{Resp: fakeResponse(t, 200, nil), Body: "x"}
	// load-time validation rejects this, but a matcher built in code bypasses
	// that path, so evaluation itself must fail closed.
	m := &Matcher{Type: "dsl", DSL: []string{`status_code ==`}}
	if checkMatcher(m, mc) {
		t.Error("an uncompilable expression must miss, not match")
	}
}

func TestCheckMatcherDSLNilResponse(t *testing.T) {
	// a matcher can run without a response; the variable environment must bind
	// zero values instead of dereferencing nil.
	mc := &MatchContext{Body: ""}
	if m := (&Matcher{Type: "dsl", DSL: []string{"status_code == 0"}}); !checkMatcher(m, mc) {
		t.Error("status_code should bind 0 with no response")
	}
	if m := (&Matcher{Type: "dsl", DSL: []string{`all_headers == ""`}}); !checkMatcher(m, mc) {
		t.Error("all_headers should bind empty with no response")
	}
}
