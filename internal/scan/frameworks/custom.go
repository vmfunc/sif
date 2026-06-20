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

/*

   BSD 3-Clause License
   (c) 2022-2026 vmfunc, xyzeva & contributors

*/

package frameworks

import (
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	charmlog "github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/output"
	"gopkg.in/yaml.v3"
)

// customDetector is a Detector defined in a user yaml file rather than compiled
// in. it scores with the same weighted signature match as the built-ins and
// optionally pulls a version out of the body.
type customDetector struct {
	BaseDetector
	versionRe    *regexp.Regexp
	versionGroup int
}

// Detect returns the weighted signature confidence and, when a version regex is
// set and matches, the captured version. confidence is the matched-weight
// fraction directly (not the built-ins' sigmoid), so it clears 0.5 only past half.
func (d *customDetector) Detect(body string, headers http.Header) (float32, string) {
	confidence := d.MatchSignatures(body, headers)
	if confidence == 0 || d.versionRe == nil {
		return confidence, ""
	}
	matches := d.versionRe.FindStringSubmatch(body)
	if len(matches) > d.versionGroup {
		return confidence, matches[d.versionGroup]
	}
	return confidence, ""
}

// signatureSpec / versionSpec / customDetectorSpec mirror the yaml on disk.
type signatureSpec struct {
	Pattern string  `yaml:"pattern"`
	Weight  float32 `yaml:"weight"`
	Header  bool    `yaml:"header"`
}

type versionSpec struct {
	Regex string `yaml:"regex"`
	Group int    `yaml:"group"`
}

type customDetectorSpec struct {
	Name       string          `yaml:"name"`
	Signatures []signatureSpec `yaml:"signatures"`
	Version    *versionSpec    `yaml:"version"`
}

// build validates the parsed spec and turns it into a Detector, so a broken
// file fails loudly instead of registering a detector that can never match.
func (spec customDetectorSpec) build() (Detector, error) {
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		return nil, fmt.Errorf("missing name")
	}
	if len(spec.Signatures) == 0 {
		return nil, fmt.Errorf("%q has no signatures", name)
	}

	sigs := make([]Signature, 0, len(spec.Signatures))
	for i, s := range spec.Signatures {
		if s.Pattern == "" {
			return nil, fmt.Errorf("%q: signature %d has an empty pattern", name, i+1)
		}
		if s.Weight <= 0 || math.IsInf(float64(s.Weight), 0) || math.IsNaN(float64(s.Weight)) {
			return nil, fmt.Errorf("%q: signature %q needs a positive, finite weight", name, s.Pattern)
		}
		sigs = append(sigs, Signature{Pattern: s.Pattern, Weight: s.Weight, HeaderOnly: s.Header})
	}

	d := &customDetector{BaseDetector: NewBaseDetector(name, sigs)}
	if spec.Version != nil {
		if spec.Version.Group < 0 {
			return nil, fmt.Errorf("%q: version group must be >= 0", name)
		}
		re, err := regexp.Compile(spec.Version.Regex)
		if err != nil {
			return nil, fmt.Errorf("%q: version regex: %w", name, err)
		}
		d.versionRe = re
		d.versionGroup = spec.Version.Group
	}
	return d, nil
}

// parseCustomDetector reads and validates one signature file.
func parseCustomDetector(path string) (Detector, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	var spec customDetectorSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return spec.build()
}

// customSignaturesDir is the per-user directory that holds yaml-defined
// detectors, alongside the user modules directory.
func customSignaturesDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Local", "sif", "signatures"), nil
	}
	return filepath.Join(home, ".config", "sif", "signatures"), nil
}

// loadCustomDetectors registers every signature file under the user directory.
// it is driven once, lazily, from DetectFramework.
func loadCustomDetectors() {
	dir, err := customSignaturesDir()
	if err != nil {
		return
	}
	loadCustomDetectorsFromDir(dir)
}

// loadCustomDetectorsFromDir registers every signature file in dir and returns
// how many loaded. a custom detector whose name matches a built-in overrides
// it, matching the user-module convention.
func loadCustomDetectorsFromDir(dir string) int {
	detectors := collectCustomDetectors(dir)
	for _, d := range detectors {
		Register(d)
	}
	if len(detectors) > 0 {
		output.Module("FRAMEWORK").Info("Loaded %d custom signatures", len(detectors))
	}
	return len(detectors)
}

// collectCustomDetectors parses (without registering) the .yaml/.yml detectors
// in dir, so discovery and validation stay pure and testable. a missing dir is
// fine; an unparseable file warns and is skipped rather than failing the scan.
func collectCustomDetectors(dir string) []Detector {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var detectors []Detector
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		switch filepath.Ext(e.Name()) {
		case ".yaml", ".yml":
		default:
			continue
		}
		d, err := parseCustomDetector(filepath.Join(dir, e.Name()))
		if err != nil {
			charmlog.Warnf("custom signature %s: %v", e.Name(), err)
			continue
		}
		detectors = append(detectors, d)
	}
	return detectors
}
