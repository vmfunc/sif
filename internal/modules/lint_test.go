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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vmfunc/sif/internal/modules"
)

// writeModule writes a module file under dir and returns its path.
func writeModule(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// findIssue reports whether any issue's message contains sub.
func findIssue(issues []modules.LintIssue, level modules.LintLevel, sub string) bool {
	for _, is := range issues {
		if is.Level == level && strings.Contains(is.Msg, sub) {
			return true
		}
	}
	return false
}

const validModule = `id: valid-mod
type: http
info:
  name: Valid
  author: sif
  severity: high
  description: a valid module
  tags: [demo]
http:
  method: GET
  paths: ["{{BaseURL}}/x"]
  matchers:
    - type: status
      status: [200]
`

func TestLintValidModule(t *testing.T) {
	dir := t.TempDir()
	writeModule(t, dir, "ok.yaml", validModule)

	report, err := modules.LintDirs([]string{dir})
	if err != nil {
		t.Fatalf("LintDirs: %v", err)
	}
	if report.HasErrors() {
		t.Errorf("valid module reported errors: %+v", report.Issues)
	}
	if report.Modules != 1 || report.Files != 1 {
		t.Errorf("counts: modules=%d files=%d, want 1/1", report.Modules, report.Files)
	}
}

func TestLintRules(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		level modules.LintLevel
		sub   string
	}{
		{
			name:  "missing name",
			body:  "id: m\ntype: http\ninfo:\n  severity: high\n  description: d\n  author: a\n  tags: [t]\nhttp:\n  paths: [\"{{BaseURL}}/\"]\n  matchers:\n    - type: status\n      status: [200]\n",
			level: modules.LintError, sub: "info.name",
		},
		{
			name:  "bad severity",
			body:  "id: m\ntype: http\ninfo:\n  name: n\n  severity: spicy\n  description: d\n  author: a\n  tags: [t]\nhttp:\n  paths: [\"{{BaseURL}}/\"]\n  matchers:\n    - type: status\n      status: [200]\n",
			level: modules.LintError, sub: "unknown severity",
		},
		{
			name:  "unknown type",
			body:  "id: m\ntype: telepathy\ninfo:\n  name: n\n  severity: high\n  description: d\n  author: a\n  tags: [t]\n",
			level: modules.LintError, sub: "unknown type",
		},
		{
			name:  "invalid regex",
			body:  "id: m\ntype: http\ninfo:\n  name: n\n  severity: high\n  description: d\n  author: a\n  tags: [t]\nhttp:\n  paths: [\"{{BaseURL}}/\"]\n  matchers:\n    - type: regex\n      regex: [\"(unclosed\"]\n",
			level: modules.LintError, sub: "invalid regex",
		},
		{
			name:  "relative path",
			body:  "id: m\ntype: http\ninfo:\n  name: n\n  severity: high\n  description: d\n  author: a\n  tags: [t]\nhttp:\n  paths: [\"/relative\"]\n  matchers:\n    - type: status\n      status: [200]\n",
			level: modules.LintError, sub: "is relative",
		},
		{
			name:  "missing author warns",
			body:  "id: m\ntype: http\ninfo:\n  name: n\n  severity: high\n  description: d\n  tags: [t]\nhttp:\n  paths: [\"{{BaseURL}}/\"]\n  matchers:\n    - type: status\n      status: [200]\n",
			level: modules.LintWarning, sub: "info.author",
		},
		{
			name:  "missing tags warns",
			body:  "id: m\ntype: http\ninfo:\n  name: n\n  author: a\n  severity: high\n  description: d\nhttp:\n  paths: [\"{{BaseURL}}/\"]\n  matchers:\n    - type: status\n      status: [200]\n",
			level: modules.LintWarning, sub: "info.tags",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeModule(t, dir, "m.yaml", tc.body)
			report, err := modules.LintDirs([]string{dir})
			if err != nil {
				t.Fatalf("LintDirs: %v", err)
			}
			if !findIssue(report.Issues, tc.level, tc.sub) {
				t.Errorf("expected a %s issue containing %q, got: %+v", tc.level, tc.sub, report.Issues)
			}
		})
	}
}

func TestLintDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	writeModule(t, dir, "a.yaml", validModule)
	// a second file with the same id but a different filename.
	writeModule(t, dir, "b.yaml", strings.Replace(validModule, "name: Valid", "name: Valid Two", 1))

	report, err := modules.LintDirs([]string{dir})
	if err != nil {
		t.Fatalf("LintDirs: %v", err)
	}
	if !findIssue(report.Issues, modules.LintError, "duplicate module id") {
		t.Errorf("expected a duplicate-id error, got: %+v", report.Issues)
	}
	// both files should carry the issue.
	n := 0
	for _, is := range report.Issues {
		if strings.Contains(is.Msg, "duplicate module id") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("duplicate id reported on %d files, want 2", n)
	}
}

func TestLintMissingDirIsSkipped(t *testing.T) {
	report, err := modules.LintDirs([]string{filepath.Join(t.TempDir(), "does-not-exist")})
	if err != nil {
		t.Fatalf("LintDirs on missing dir: %v", err)
	}
	if report.Files != 0 || len(report.Issues) != 0 {
		t.Errorf("missing dir should produce nothing, got files=%d issues=%d", report.Files, len(report.Issues))
	}
}
