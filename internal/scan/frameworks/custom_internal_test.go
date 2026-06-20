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

package frameworks

import (
	"math"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestCustomDetectorSpecBuild(t *testing.T) {
	valid := customDetectorSpec{
		Name:       "Ghost",
		Signatures: []signatureSpec{{Pattern: `content="Ghost`, Weight: 1.0}},
	}
	cases := []struct {
		name    string
		spec    customDetectorSpec
		wantErr bool
	}{
		{"valid", valid, false},
		{"empty name", customDetectorSpec{Signatures: valid.Signatures}, true},
		{"whitespace name", customDetectorSpec{Name: "  ", Signatures: valid.Signatures}, true},
		{"no signatures", customDetectorSpec{Name: "X"}, true},
		{"empty pattern", customDetectorSpec{Name: "X", Signatures: []signatureSpec{{Pattern: "", Weight: 1}}}, true},
		{"zero weight", customDetectorSpec{Name: "X", Signatures: []signatureSpec{{Pattern: "p", Weight: 0}}}, true},
		{"negative weight", customDetectorSpec{Name: "X", Signatures: []signatureSpec{{Pattern: "p", Weight: -1}}}, true},
		{"bad version regex", customDetectorSpec{Name: "X", Signatures: []signatureSpec{{Pattern: "p", Weight: 1}}, Version: &versionSpec{Regex: "("}}, true},
		{"negative version group", customDetectorSpec{Name: "X", Signatures: valid.Signatures, Version: &versionSpec{Regex: `v([0-9]+)`, Group: -1}}, true},
		{"nan weight", customDetectorSpec{Name: "X", Signatures: []signatureSpec{{Pattern: "p", Weight: float32(math.NaN())}}}, true},
		{"inf weight", customDetectorSpec{Name: "X", Signatures: []signatureSpec{{Pattern: "p", Weight: float32(math.Inf(1))}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.spec.build(); (err != nil) != tc.wantErr {
				t.Fatalf("build() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestCustomDetectorDetect(t *testing.T) {
	// the version regex is independent of the signature patterns so a body that
	// matches it but no signature still must not surface a version.
	spec := customDetectorSpec{
		Name: "Acme",
		Signatures: []signatureSpec{
			{Pattern: "AcmeCMS", Weight: 0.6},
			{Pattern: "X-Acme", Weight: 0.4, Header: true},
		},
		Version: &versionSpec{Regex: `ver=([0-9.]+)`, Group: 1},
	}
	d, err := spec.build()
	if err != nil {
		t.Fatal(err)
	}

	withHeader := func() http.Header {
		h := http.Header{}
		h.Set("X-Acme", "1")
		return h
	}

	t.Run("all signatures match: confidence 1, version extracted", func(t *testing.T) {
		conf, ver := d.Detect("powered by AcmeCMS ver=4.2.0", withHeader())
		if conf != 1.0 {
			t.Errorf("confidence = %v, want 1.0", conf)
		}
		if ver != "4.2.0" {
			t.Errorf("version = %q, want 4.2.0", ver)
		}
	})

	t.Run("only body signature matches: linear 0.6", func(t *testing.T) {
		conf, ver := d.Detect("powered by AcmeCMS", http.Header{})
		if conf != 0.6 {
			t.Errorf("confidence = %v, want 0.6 (0.6/1.0 matched fraction)", conf)
		}
		if ver != "" {
			t.Errorf("version = %q, want empty", ver)
		}
	})

	t.Run("no signature matches: 0 confidence, no version even when present", func(t *testing.T) {
		conf, ver := d.Detect("ver=9.9.9 but no marker here", http.Header{})
		if conf != 0 {
			t.Errorf("confidence = %v, want 0", conf)
		}
		if ver != "" {
			t.Errorf("version = %q, want empty (not detected, so not extracted)", ver)
		}
	})
}

func TestParseCustomDetectorFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fw.yaml")
	content := `name: Parsed
signatures:
  - pattern: "Marker"
    weight: 0.5
  - pattern: "X-Hdr"
    weight: 0.5
    header: true
version:
  regex: 'Parsed/([0-9.]+)'
  group: 1
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	d, err := parseCustomDetector(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Name() != "Parsed" {
		t.Errorf("name = %q, want Parsed", d.Name())
	}
	if len(d.Signatures()) != 2 {
		t.Errorf("signatures = %d, want 2", len(d.Signatures()))
	}

	h := http.Header{}
	h.Set("X-Hdr", "1")
	conf, ver := d.Detect("Marker Parsed/3.1", h)
	if conf != 1.0 {
		t.Errorf("confidence = %v, want 1.0", conf)
	}
	if ver != "3.1" {
		t.Errorf("version = %q, want 3.1", ver)
	}
}

func TestCollectCustomDetectors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("good.yaml", "name: ZZCustomTest\nsignatures:\n  - pattern: \"ZZCustomMarker\"\n    weight: 1.0\n")
	write("bad.yaml", "name: \"\"\nsignatures: []\n") // invalid: skipped with a warning
	write("ignore.txt", "not a signature file")       // wrong extension: ignored

	got := collectCustomDetectors(dir)
	if len(got) != 1 {
		t.Fatalf("collected %d detectors, want 1 (good.yaml only)", len(got))
	}
	if got[0].Name() != "ZZCustomTest" {
		t.Errorf("detector name = %q, want ZZCustomTest", got[0].Name())
	}
	if conf, _ := got[0].Detect("page with ZZCustomMarker", http.Header{}); conf != 1.0 {
		t.Errorf("confidence = %v, want 1.0", conf)
	}
}

func TestCollectCustomDetectorsMissingDir(t *testing.T) {
	if got := collectCustomDetectors(filepath.Join(t.TempDir(), "nope")); got != nil {
		t.Errorf("missing dir should yield nil, got %v", got)
	}
}
