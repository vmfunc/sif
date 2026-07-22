package frameworks

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vmfunc/sif/internal/output"
)

// TestLegacyCustomSignatureDeprecationLogged extends the backcompat proof in
// TestLegacyCustomSignatureStillLoads (custom_backcompat_test.go): the legacy
// signatures/ dir must keep loading AND now also emit one deprecation notice
// steering users at the unified fingerprint-module surface. it must not fail,
// stop loading, or migrate anything.
func TestLegacyCustomSignatureDeprecationLogged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.yaml")
	yamlSrc := "name: acme\n" +
		"signatures:\n" +
		"  - pattern: \"X-Acme\"\n" +
		"    weight: 1\n" +
		"    header: true\n"
	if err := os.WriteFile(path, []byte(yamlSrc), 0o600); err != nil {
		t.Fatal(err)
	}

	var n int
	stdout := captureStdout(t, func() {
		n = loadCustomDetectorsFromDir(dir)
	})

	if n != 1 {
		t.Fatalf("loadCustomDetectorsFromDir loaded %d detectors, want 1", n)
	}
	if _, ok := GetDetector("acme"); !ok {
		t.Fatal("acme detector did not register")
	}
	if !strings.Contains(stdout, "Loaded 1 custom signatures") {
		t.Fatalf("missing load-count line, got: %q", stdout)
	}
	if !strings.Contains(stdout, "deprecated") {
		t.Fatalf("missing deprecation notice, got: %q", stdout)
	}
}

// captureStdout swaps os.Stdout for a pipe and repoints output's sink at it
// via SetSilent(false), which reads os.Stdout at call time (see
// internal/output/silent_test.go for the same idiom), then runs fn and
// returns everything written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w
	output.SetSilent(false)

	ch := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		ch <- string(data)
	}()

	fn()

	os.Stdout = saved
	output.SetSilent(false)
	w.Close()
	return <-ch
}
