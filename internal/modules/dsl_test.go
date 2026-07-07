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
