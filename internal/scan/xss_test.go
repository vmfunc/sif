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

package scan

import (
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// reflectsRaw echoes the named param straight into html text, so the breaking
// chars survive unescaped - a reflected xss sink.
func reflectsRaw(param string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		//nolint:gosec // deliberate reflected-xss fixture for the probe under test
		w.Write([]byte("<html><body><div>" + v + "</div></body></html>"))
	}))
}

// reflectsQuotesInText echoes the param into element text but escapes only the
// angle brackets, the way an encoder limited to < > & does. quotes survive raw,
// yet in text context they delimit nothing, so this is not an injection sink.
func reflectsQuotesInText(param string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		v = strings.ReplaceAll(v, "<", "&lt;")
		v = strings.ReplaceAll(v, ">", "&gt;")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		//nolint:gosec // fixture: quotes raw in element text is not exploitable
		w.Write([]byte("<html><body><p>no results for " + v + "</p></body></html>"))
	}))
}

// reflectsInAttribute echoes the param into a tag attribute value with the angle
// brackets escaped but quotes raw. a surviving quote closes the value and breaks
// out, so this is a genuine attribute-context sink the fix must still report.
func reflectsInAttribute(param string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		v = strings.ReplaceAll(v, "<", "&lt;")
		v = strings.ReplaceAll(v, ">", "&gt;")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		//nolint:gosec // deliberate attribute-context xss fixture for the probe under test
		w.Write([]byte(`<html><body><input value="` + v + `"></body></html>`))
	}))
}

func TestXSS_DetectsRawHTMLReflection(t *testing.T) {
	srv := reflectsRaw("q")
	defer srv.Close()

	result, err := XSS(srv.URL, 5*time.Second, 4, "")
	if err != nil {
		t.Fatalf("XSS: %v", err)
	}
	if result == nil || len(result.Findings) == 0 {
		t.Fatalf("expected reflected xss findings, got %+v", result)
	}

	var found *XSSFinding
	for i := range result.Findings {
		if result.Findings[i].Parameter == "q" {
			found = &result.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a finding on param 'q', got %+v", result.Findings)
	}
	if found.Context != "html" {
		t.Errorf("expected html context, got %s", found.Context)
	}
	if len(found.SurvivedRaw) == 0 {
		t.Errorf("expected surviving breaking chars, got none")
	}
}

func TestXSS_NoFalsePositiveWhenEscaped(t *testing.T) {
	// the server html-escapes the reflection, so no breaking char survives raw.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body><div>" + html.EscapeString(v) + "</div></body></html>"))
	}))
	defer srv.Close()

	result, err := XSS(srv.URL, 5*time.Second, 4, "")
	if err != nil {
		t.Fatalf("XSS: %v", err)
	}
	if result != nil && len(result.Findings) > 0 {
		t.Errorf("expected no findings when reflection is escaped, got %+v", result.Findings)
	}
}

func TestXSS_NoFalsePositiveWhenNotReflected(t *testing.T) {
	// never echoes the input back, so nothing is injectable.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>static page</body></html>"))
	}))
	defer srv.Close()

	result, err := XSS(srv.URL, 5*time.Second, 4, "")
	if err != nil {
		t.Fatalf("XSS: %v", err)
	}
	if result != nil && len(result.Findings) > 0 {
		t.Errorf("expected no findings on static page, got %+v", result.Findings)
	}
}

func TestXSS_NoFalsePositiveOnQuotesInText(t *testing.T) {
	srv := reflectsQuotesInText("q")
	defer srv.Close()

	result, err := XSS(srv.URL, 5*time.Second, 4, "")
	if err != nil {
		t.Fatalf("XSS: %v", err)
	}
	if result != nil && len(result.Findings) > 0 {
		t.Errorf("quotes reflected in element text are inert; expected no findings, got %+v", result.Findings)
	}
}

func TestXSS_DetectsAttributeReflection(t *testing.T) {
	srv := reflectsInAttribute("q")
	defer srv.Close()

	result, err := XSS(srv.URL, 5*time.Second, 4, "")
	if err != nil {
		t.Fatalf("XSS: %v", err)
	}
	if result == nil || len(result.Findings) == 0 {
		t.Fatalf("expected an attribute-context finding, got %+v", result)
	}

	var found *XSSFinding
	for i := range result.Findings {
		if result.Findings[i].Parameter == "q" {
			found = &result.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("expected a finding on param 'q', got %+v", result.Findings)
	}
	if found.Context != "attribute" {
		t.Errorf("expected attribute context, got %s", found.Context)
	}
}

func TestClassifyXSSContext(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "live html tag",
			body: "<div><" + canaryToken + "></div>",
			want: "html",
		},
		{
			name: "inside script block",
			body: "<script>var x = '" + canaryToken + "';</script>",
			want: "script",
		},
		{
			name: "attribute value",
			body: `<input value="` + canaryToken + `">`,
			want: "attribute",
		},
		{
			name: "escaped brackets in element text",
			body: `<p>no results for &lt;` + canaryToken + `&gt;"` + canaryToken + `'</p>`,
			want: "text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyXSSContext(tt.body); got != tt.want {
				t.Errorf("classifyXSSContext() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSurvivingBreakChars(t *testing.T) {
	// the canary is wrapped exactly as the probe injects it; all five chars survive.
	body := "<" + canaryToken + ">\"" + canaryToken + "'`" + canaryToken + "`"
	got := survivingBreakChars(body)
	want := map[string]bool{"<": true, ">": true, "\"": true, "'": true, "`": true}
	if len(got) != len(want) {
		t.Fatalf("expected %d surviving chars, got %v", len(want), got)
	}
	for _, c := range got {
		if !want[c] {
			t.Errorf("unexpected surviving char %q", c)
		}
	}
}

func TestXSSResult_ResultType(t *testing.T) {
	r := &XSSResult{}
	if r.ResultType() != "xss" {
		t.Errorf("expected result type 'xss', got %q", r.ResultType())
	}
}
