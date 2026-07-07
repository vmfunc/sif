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
	"regexp"

	"github.com/vmfunc/sif/internal/scan/frameworks"
)

// bridgeableToFramework reports whether def is a fingerprint whose semantics
// the framework engine can reproduce exactly: root path, default confidence,
// all weights > 0 (the shared domain). anything else stays module-only.
//
// even on this domain the firing boundary still differs at score == 0.5: the
// module engine fires at score >= confidence, the framework engine at
// score > detectionThreshold. that residual is intentional, see bridgeFingerprint.
func bridgeableToFramework(def *YAMLModule) (bool, string) {
	if def.Type != TypeFingerprint || def.Fingerprint == nil {
		return false, "not a fingerprint module"
	}
	cfg := def.Fingerprint
	if cfg.Path != "" && cfg.Path != "/" {
		return false, "non-root path"
	}
	if cfg.Confidence != 0 {
		return false, "custom confidence"
	}
	for _, s := range cfg.Signatures {
		if s.Weight <= 0 {
			return false, "zero-weight signature"
		}
	}
	return true, ""
}

// bridgeFingerprint registers def as a framework detector when
// bridgeableToFramework allows it, and reports whether it registered. a guard
// failure is not an error: the module still runs natively in the module
// engine, so bridging is pure upside or a no-op.
func bridgeFingerprint(def *YAMLModule) (bool, string) {
	ok, reason := bridgeableToFramework(def)
	if !ok {
		return false, reason
	}

	cfg := def.Fingerprint
	sigs := make([]frameworks.Signature, len(cfg.Signatures))
	for i, s := range cfg.Signatures {
		sigs[i] = frameworks.Signature{Pattern: s.Pattern, Weight: s.Weight, HeaderOnly: s.Header}
	}

	d := &bridgedDetector{BaseDetector: frameworks.NewBaseDetector(def.ID, sigs)}
	if cfg.Version != nil {
		if re, err := regexp.Compile(cfg.Version.Regex); err == nil {
			d.versionRe = re
			d.versionGroup = cfg.Version.Group
		}
	}

	frameworks.Register(d)
	return true, ""
}

// bridgedDetector adapts a bridgeable fingerprint module into a
// frameworks.Detector. structurally the same as frameworks' own (unexported)
// customDetector; kept as a small local copy here rather than exporting that
// type, since frameworks cannot import modules and this avoids an import cycle.
type bridgedDetector struct {
	frameworks.BaseDetector
	versionRe    *regexp.Regexp
	versionGroup int
}

// Detect mirrors customDetector.Detect (custom.go): the weighted signature
// score plus an optional version capture.
func (d *bridgedDetector) Detect(body string, headers http.Header) (float32, string) {
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

// BridgeFingerprints registers every already-loaded type: fingerprint module
// as a framework detector where bridgeableToFramework allows it. modules
// outside that domain are left untouched and keep running only in the module
// engine; bridging never removes or alters a module's native execution.
func BridgeFingerprints() {
	for _, m := range ByType(TypeFingerprint) {
		w, ok := m.(*yamlModuleWrapper)
		if !ok {
			continue
		}
		bridgeFingerprint(w.definition())
	}
}
