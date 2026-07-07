package frameworks

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyCustomSignatureStillLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acme.yaml")
	yaml := "name: acme\n" +
		"signatures:\n" +
		"  - pattern: \"X-Acme\"\n" +
		"    weight: 1\n" +
		"    header: true\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	det, err := parseCustomDetector(path)
	if err != nil {
		t.Fatalf("parseCustomDetector: %v", err)
	}
	h := http.Header{}
	h.Add("X-Acme", "1")
	score, _ := det.Detect("", h)
	if score != 1 {
		t.Fatalf("score = %v, want 1", score)
	}
}
