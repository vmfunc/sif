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

// fakeResponse builds a minimal *http.Response for matcher/extractor tests.
// it carries no real socket (Body is http.NoBody), so there is nothing to
// close; bodyclose is excluded for test files in .golangci.yml. header drives
// the header/all parts without a live server; matchers read the body string
// argument, not resp.Body.
func fakeResponse(t *testing.T, status int, header http.Header) *http.Response {
	t.Helper()
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: header, Body: http.NoBody}
}

func TestCheckMatcherStatus(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   []int
		expect bool
	}{
		{name: "single match", status: 200, want: []int{200}, expect: true},
		{name: "one of many", status: 404, want: []int{200, 301, 404}, expect: true},
		{name: "no match", status: 500, want: []int{200, 404}, expect: false},
		{name: "empty status list", status: 200, want: nil, expect: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Matcher{Type: "status", Status: tt.want}
			resp := fakeResponse(t, tt.status, nil)
			if got := checkMatcher(m, resp, ""); got != tt.expect {
				t.Errorf("checkMatcher status = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestCheckMatcherWord(t *testing.T) {
	const body = "welcome admin dashboard"

	tests := []struct {
		name      string
		words     []string
		condition string
		expect    bool
	}{
		{name: "and all present", words: []string{"admin", "dashboard"}, condition: "and", expect: true},
		{name: "and one missing", words: []string{"admin", "missing"}, condition: "and", expect: false},
		{name: "default is and", words: []string{"admin", "missing"}, condition: "", expect: false},
		{name: "or one present", words: []string{"missing", "admin"}, condition: "or", expect: true},
		{name: "or none present", words: []string{"missing", "absent"}, condition: "or", expect: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Matcher{Type: "word", Part: "body", Words: tt.words, Condition: tt.condition}
			resp := fakeResponse(t, 200, nil)
			if got := checkMatcher(m, resp, body); got != tt.expect {
				t.Errorf("checkMatcher word = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestCheckMatcherRegex(t *testing.T) {
	const body = "version 1.2.3 build 99"

	tests := []struct {
		name      string
		patterns  []string
		condition string
		expect    bool
	}{
		{name: "and all match", patterns: []string{`version \d`, `build \d+`}, condition: "and", expect: true},
		{name: "and one fails", patterns: []string{`version \d`, `nope\d`}, condition: "and", expect: false},
		{name: "or one matches", patterns: []string{`nope`, `build \d+`}, condition: "or", expect: true},
		{name: "or none match", patterns: []string{`nope`, `zilch`}, condition: "or", expect: false},
		// an invalid pattern under AND must fail closed, not panic.
		{name: "and invalid pattern fails closed", patterns: []string{`version \d`, `(`}, condition: "and", expect: false},
		// under OR an invalid pattern is skipped, a later valid one can still hit.
		{name: "or invalid pattern skipped", patterns: []string{`(`, `build \d+`}, condition: "or", expect: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Matcher{Type: "regex", Part: "body", Regex: tt.patterns, Condition: tt.condition}
			resp := fakeResponse(t, 200, nil)
			if got := checkMatcher(m, resp, body); got != tt.expect {
				t.Errorf("checkMatcher regex = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestCheckMatcherHeaderPart(t *testing.T) {
	header := http.Header{"X-Powered-By": []string{"PHP/8.1"}}
	resp := fakeResponse(t, 200, header)

	m := &Matcher{Type: "word", Part: "header", Words: []string{"PHP/8.1"}}
	if !checkMatcher(m, resp, "body-content") {
		t.Error("expected header-part word matcher to hit on header value")
	}

	// the same word lives only in the header, so a body-part matcher must miss.
	mBody := &Matcher{Type: "word", Part: "body", Words: []string{"PHP/8.1"}}
	if checkMatcher(mBody, resp, "body-content") {
		t.Error("body-part matcher should not see header-only value")
	}
}

func TestCheckMatcherUnknownType(t *testing.T) {
	m := &Matcher{Type: "size", Part: "body"}
	resp := fakeResponse(t, 200, nil)
	if checkMatcher(m, resp, "anything") {
		t.Error("unknown matcher type should not match")
	}
}

func TestCheckMatchers(t *testing.T) {
	resp := fakeResponse(t, 200, http.Header{"Server": []string{"nginx"}})
	const body = "secret token here"

	tests := []struct {
		name     string
		matchers []Matcher
		expect   bool
	}{
		{
			name:     "empty matchers never match",
			matchers: nil,
			expect:   false,
		},
		{
			name: "all matchers pass (AND across matchers)",
			matchers: []Matcher{
				{Type: "status", Status: []int{200}},
				{Type: "word", Part: "body", Words: []string{"secret"}},
			},
			expect: true,
		},
		{
			name: "one matcher fails breaks AND",
			matchers: []Matcher{
				{Type: "status", Status: []int{200}},
				{Type: "word", Part: "body", Words: []string{"absent"}},
			},
			expect: false,
		},
		{
			name: "negative inverts a non-match into a pass",
			matchers: []Matcher{
				{Type: "word", Part: "body", Words: []string{"absent"}, Negative: true},
			},
			expect: true,
		},
		{
			name: "negative inverts a match into a fail",
			matchers: []Matcher{
				{Type: "word", Part: "body", Words: []string{"secret"}, Negative: true},
			},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkMatchers(tt.matchers, resp, body); got != tt.expect {
				t.Errorf("checkMatchers = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestCheckWords(t *testing.T) {
	const content = "alpha beta gamma"

	tests := []struct {
		name      string
		words     []string
		condition string
		expect    bool
	}{
		{name: "and all present", words: []string{"alpha", "gamma"}, condition: "and", expect: true},
		{name: "and missing", words: []string{"alpha", "delta"}, condition: "and", expect: false},
		{name: "or present", words: []string{"delta", "beta"}, condition: "or", expect: true},
		{name: "or absent", words: []string{"delta", "epsilon"}, condition: "or", expect: false},
		{name: "empty under and matches vacuously", words: nil, condition: "and", expect: true},
		{name: "empty under or matches nothing", words: nil, condition: "or", expect: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkWords(content, tt.words, tt.condition); got != tt.expect {
				t.Errorf("checkWords = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestCheckRegex(t *testing.T) {
	const content = "id=42 name=root"

	tests := []struct {
		name      string
		patterns  []string
		condition string
		expect    bool
	}{
		{name: "and all match", patterns: []string{`id=\d+`, `name=\w+`}, condition: "and", expect: true},
		{name: "and one fails", patterns: []string{`id=\d+`, `zzz`}, condition: "and", expect: false},
		{name: "or first matches", patterns: []string{`id=\d+`, `zzz`}, condition: "or", expect: true},
		{name: "or none match", patterns: []string{`xxx`, `zzz`}, condition: "or", expect: false},
		{name: "and bad regex fails closed", patterns: []string{`(`}, condition: "and", expect: false},
		{name: "or bad regex skipped then match", patterns: []string{`(`, `name=\w+`}, condition: "or", expect: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkRegex(content, tt.patterns, tt.condition); got != tt.expect {
				t.Errorf("checkRegex = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestGetPart(t *testing.T) {
	header := http.Header{"Server": []string{"nginx"}}
	resp := fakeResponse(t, 200, header)
	const body = "page body"

	if got := getPart("body", resp, body); got != body {
		t.Errorf("getPart body = %q, want %q", got, body)
	}

	headerPart := getPart("header", resp, body)
	if !strings.Contains(headerPart, "Server") || !strings.Contains(headerPart, "nginx") {
		t.Errorf("getPart header = %q, want it to include the header", headerPart)
	}
	if strings.Contains(headerPart, body) {
		t.Errorf("getPart header should not include body, got %q", headerPart)
	}

	all := getPart("all", resp, body)
	if !strings.Contains(all, "nginx") || !strings.Contains(all, body) {
		t.Errorf("getPart all = %q, want both header and body", all)
	}

	// an unrecognised part falls back to the body.
	if got := getPart("weird", resp, body); got != body {
		t.Errorf("getPart fallback = %q, want body %q", got, body)
	}

	// empty part behaves like "all".
	if got := getPart("", resp, body); !strings.Contains(got, "nginx") || !strings.Contains(got, body) {
		t.Errorf("getPart empty = %q, want both header and body", got)
	}
}

func TestRunExtractors(t *testing.T) {
	resp := fakeResponse(t, 200, http.Header{"X-Token": []string{"abc123"}})
	const body = `{"session":"sess-7788","role":"admin"}`

	tests := []struct {
		name       string
		extractors []Extractor
		wantKey    string
		wantVal    string
		wantNil    bool
	}{
		{
			name:       "no extractors yields nil",
			extractors: nil,
			wantNil:    true,
		},
		{
			name: "regex capture group on body",
			extractors: []Extractor{
				{Type: "regex", Name: "session", Part: "body", Regex: []string{`"session":"([^"]+)"`}, Group: 1},
			},
			wantKey: "session",
			wantVal: "sess-7788",
		},
		{
			name: "group zero is the whole match",
			extractors: []Extractor{
				{Type: "regex", Name: "role", Part: "body", Regex: []string{`role":"admin`}, Group: 0},
			},
			wantKey: "role",
			wantVal: `role":"admin`,
		},
		{
			name: "extract from header part",
			extractors: []Extractor{
				{Type: "regex", Name: "token", Part: "header", Regex: []string{`X-Token: (\S+)`}, Group: 1},
			},
			wantKey: "token",
			wantVal: "abc123",
		},
		{
			name: "first matching pattern wins",
			extractors: []Extractor{
				{Type: "regex", Name: "session", Part: "body", Regex: []string{`nomatch(\d+)`, `"session":"([^"]+)"`}, Group: 1},
			},
			wantKey: "session",
			wantVal: "sess-7788",
		},
		{
			name: "group index out of range is skipped",
			extractors: []Extractor{
				{Type: "regex", Name: "session", Part: "body", Regex: []string{`"session":"([^"]+)"`}, Group: 5},
			},
			wantNil: true,
		},
		{
			name: "invalid pattern is skipped, no capture",
			extractors: []Extractor{
				{Type: "regex", Name: "session", Part: "body", Regex: []string{`(`}, Group: 1},
			},
			wantNil: true,
		},
		{
			name: "unknown extractor type is ignored",
			extractors: []Extractor{
				{Type: "bogus", Name: "session", Part: "body", Regex: []string{`"session":"([^"]+)"`}, Group: 1},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runExtractors(tt.extractors, resp, body)
			if tt.wantNil {
				if len(got) != 0 {
					t.Errorf("runExtractors = %v, want empty", got)
				}
				return
			}
			if got[tt.wantKey] != tt.wantVal {
				t.Errorf("runExtractors[%q] = %q, want %q", tt.wantKey, got[tt.wantKey], tt.wantVal)
			}
		})
	}
}

func TestSubstituteVariables(t *testing.T) {
	tests := []struct {
		name     string
		template string
		baseURL  string
		payload  string
		want     string
	}{
		{
			name:     "baseurl both cases",
			template: "{{BaseURL}}/x and {{baseurl}}/y",
			baseURL:  "http://h",
			want:     "http://h/x and http://h/y",
		},
		{
			name:     "payload both cases",
			template: "q={{payload}}&r={{Payload}}",
			payload:  "<script>",
			want:     "q=<script>&r=<script>",
		},
		{
			name:     "combined base and payload",
			template: "{{BaseURL}}/search?q={{payload}}",
			baseURL:  "http://h",
			payload:  "x",
			want:     "http://h/search?q=x",
		},
		{
			name:     "no placeholders untouched",
			template: "/static/path",
			baseURL:  "http://h",
			want:     "/static/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := substituteVariables(tt.template, tt.baseURL, tt.payload); got != tt.want {
				t.Errorf("substituteVariables = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerateHTTPRequests(t *testing.T) {
	t.Run("paths without payloads", func(t *testing.T) {
		cfg := &HTTPConfig{
			Paths: []string{"{{BaseURL}}/a", "{{BaseURL}}/b"},
		}
		// trailing slash on the target must be trimmed before substitution.
		got := generateHTTPRequests("http://h/", cfg)
		if len(got) != 2 {
			t.Fatalf("got %d requests, want 2", len(got))
		}
		if got[0].Method != "GET" {
			t.Errorf("default method = %q, want GET", got[0].Method)
		}
		if got[0].URL != "http://h/a" || got[1].URL != "http://h/b" {
			t.Errorf("urls = %q,%q", got[0].URL, got[1].URL)
		}
	})

	t.Run("payload expansion is path x payload", func(t *testing.T) {
		cfg := &HTTPConfig{
			Method:   "POST",
			Paths:    []string{"{{BaseURL}}/q?x={{payload}}"},
			Payloads: []string{"1", "2", "3"},
			Body:     "data={{payload}}",
		}
		got := generateHTTPRequests("http://h", cfg)
		if len(got) != 3 {
			t.Fatalf("got %d requests, want 3", len(got))
		}
		for i, want := range []string{"1", "2", "3"} {
			if got[i].Payload != want {
				t.Errorf("req %d payload = %q, want %q", i, got[i].Payload, want)
			}
			if got[i].URL != "http://h/q?x="+want {
				t.Errorf("req %d url = %q", i, got[i].URL)
			}
			if got[i].Body != "data="+want {
				t.Errorf("req %d body = %q", i, got[i].Body)
			}
			if got[i].Method != "POST" {
				t.Errorf("req %d method = %q, want POST", i, got[i].Method)
			}
		}
	})

	t.Run("multiple paths times multiple payloads", func(t *testing.T) {
		cfg := &HTTPConfig{
			Paths:    []string{"{{BaseURL}}/a", "{{BaseURL}}/b"},
			Payloads: []string{"x", "y"},
		}
		got := generateHTTPRequests("http://h", cfg)
		if len(got) != 4 {
			t.Fatalf("got %d requests, want 4 (2 paths x 2 payloads)", len(got))
		}
	})
}
