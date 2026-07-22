package js

import (
	"regexp"
	"strings"
	"testing"
)

func TestProbe_EndpointFalsePositives(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"regex literal flags", `str.replace("/gi", x)`},
		{"date format string", `format(d, "dd/mm/yyyy")`},
		{"regex char class", `"[a-z]/g"`},
		{"math expression in string", `"1/2 cup"`},
		{"comment prose", `// see docs at ./foo/bar for details`},
	}
	for _, c := range cases {
		got := ExtractEndpoints(c.content, "https://example.com/app.js")
		t.Logf("%-24s input=%-40q => %v", c.name, c.content, got)
	}
	// log (don't fail) whether the regex-literal FP is present
	got := ExtractEndpoints(`x.replace("/gi", "")`, "https://example.com/a.js")
	found := false
	for _, e := range got {
		if strings.Contains(e, "/gi") {
			found = true
		}
	}
	if found {
		t.Log("CONFIRMED: '/gi' regex-flag literal reported as an endpoint (false positive)")
	} else {
		t.Log("note: /gi not reported")
	}
}

// note: a RE2-backtracking probe was removed here: Go's regexp is RE2 and
// linear by construction, so a wall-clock timing assertion added only flake
// under -race load, not coverage.

// version/entropy extraction is not in the js pkg; this documents the shape
// of the aws-secret capture group instead.
func TestProbe_AwsSecretCaptureGroup(t *testing.T) {
	re := regexp.MustCompile(`\b((?:aws_secret_access_key|aws_secret|secret_key)["']?\s*[:=]\s*["']?)([A-Za-z0-9/+]{40})\b`)
	m := re.FindStringSubmatch(`aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`)
	if m == nil {
		t.Fatal("no match")
	}
	t.Logf("group2 (reported value) = %q", m[2])
}
