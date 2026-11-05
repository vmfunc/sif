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
	"bytes"
	"strings"
	"testing"

	"github.com/vmfunc/sif/internal/modules"
)

const lintableModule = `id: cli-mod
type: http
info:
  name: CLI
  author: sif
  severity: high
  description: a module
  tags: [demo]
http:
  method: GET
  paths: ["{{BaseURL}}/x"]
  matchers:
    - type: word
      part: body
      words: ["leak"]
tests:
  - name: flags a leak
    response: {status: 200, body: "leak found"}
    expect: {match: true}
  - name: clean body is fine
    response: {status: 200, body: "clean"}
    expect: {match: false}
`

func runCmd(args []string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = modules.RunCommand(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRunCommandLintPass(t *testing.T) {
	dir := t.TempDir()
	writeModule(t, dir, "m.yaml", lintableModule)

	code, stdout, _ := runCmd([]string{"lint", dir})
	if code != 0 {
		t.Fatalf("lint exit = %d, want 0", code)
	}
	if !strings.Contains(stdout, "0 error(s)") {
		t.Errorf("summary missing from stdout: %q", stdout)
	}
}

func TestRunCommandLintFail(t *testing.T) {
	dir := t.TempDir()
	writeModule(t, dir, "bad.yaml", "id: bad\ntype: http\ninfo:\n  severity: nope\nhttp:\n  paths: [\"/rel\"]\n  matchers:\n    - type: status\n      status: [200]\n")

	code, _, stderr := runCmd([]string{"lint", dir})
	if code != 1 {
		t.Fatalf("lint exit = %d, want 1", code)
	}
	if !strings.Contains(stderr, "error:") {
		t.Errorf("expected errors on stderr, got: %q", stderr)
	}
}

func TestRunCommandTestPass(t *testing.T) {
	dir := t.TempDir()
	writeModule(t, dir, "m.yaml", lintableModule)

	code, stdout, _ := runCmd([]string{"test", dir})
	if code != 0 {
		t.Fatalf("test exit = %d, want 0", code)
	}
	if !strings.Contains(stdout, "2 passed, 0 failed") {
		t.Errorf("summary missing from stdout: %q", stdout)
	}
}

func TestRunCommandTestFailsOnWrongExpectation(t *testing.T) {
	dir := t.TempDir()
	// same module but with a test that asserts the wrong verdict.
	body := strings.Replace(lintableModule,
		"  - name: clean body is fine\n    response: {status: 200, body: \"clean\"}\n    expect: {match: false}\n",
		"  - name: clean body wrongly expected to match\n    response: {status: 200, body: \"clean\"}\n    expect: {match: true}\n", 1)
	writeModule(t, dir, "m.yaml", body)

	code, _, stderr := runCmd([]string{"test", dir})
	if code != 1 {
		t.Fatalf("test exit = %d, want 1", code)
	}
	if !strings.Contains(stderr, "FAIL") {
		t.Errorf("expected a FAIL line on stderr, got: %q", stderr)
	}
}

func TestRunCommandTestNamedFileWithoutTests(t *testing.T) {
	dir := t.TempDir()
	path := writeModule(t, dir, "notests.yaml", validModule)

	code, _, stderr := runCmd([]string{"test", path})
	if code != 1 {
		t.Fatalf("test exit = %d, want 1 for an explicit file with no tests", code)
	}
	if !strings.Contains(stderr, "no tests") {
		t.Errorf("expected a no-tests error, got: %q", stderr)
	}
}

func TestRunCommandUsage(t *testing.T) {
	if code, _, _ := runCmd(nil); code != 2 {
		t.Errorf("no args exit = %d, want 2", code)
	}
	if code, _, stderr := runCmd([]string{"bogus"}); code != 2 || !strings.Contains(stderr, "unknown subcommand") {
		t.Errorf("bogus subcommand: code=%d stderr=%q", code, stderr)
	}
	if code, stdout, _ := runCmd([]string{"help"}); code != 0 || !strings.Contains(stdout, "usage: sif modules") {
		t.Errorf("help: code=%d stdout=%q", code, stdout)
	}
}
