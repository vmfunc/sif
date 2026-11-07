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
	"context"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"

	"github.com/vmfunc/sif/internal/httpx"
)

// FingerprintConfig defines a framework-fingerprint module: weighted body/header
// signatures scored into a confidence, plus an optional version regex. It mirrors
// the framework custom-detector format so user fingerprints and modules can share
// one loader and directory.
type FingerprintConfig struct {
	Path       string        `yaml:"path,omitempty"`       // request path, default "/"
	Confidence float32       `yaml:"confidence,omitempty"` // min score to fire, default 0.5
	Signatures []FPSignature `yaml:"signatures"`
	Version    *FPVersion    `yaml:"version,omitempty"`
}

// FPSignature is one weighted pattern. Header matches the response headers (name
// or value, case-insensitive) instead of the body.
type FPSignature struct {
	Pattern string  `yaml:"pattern"`
	Weight  float32 `yaml:"weight"`
	Header  bool    `yaml:"header"`
}

// FPVersion pulls a version string out of the body via a capture group.
type FPVersion struct {
	Regex string `yaml:"regex"`
	Group int    `yaml:"group"`
}

// defaultFingerprintConfidence is the score a fingerprint must reach to fire when
// the module does not set its own threshold.
const defaultFingerprintConfidence = 0.5

// validateFingerprint rejects a fingerprint config that can never produce a
// meaningful score, so a broken module fails at load instead of silently never
// matching. An omitted signature weight defaults to 1, so 0 is allowed.
func validateFingerprint(cfg *FingerprintConfig) error {
	if cfg == nil {
		return fmt.Errorf("missing fingerprint configuration")
	}
	if len(cfg.Signatures) == 0 {
		return fmt.Errorf("fingerprint requires at least one signature")
	}
	for i, s := range cfg.Signatures {
		if s.Pattern == "" {
			return fmt.Errorf("signature %d has an empty pattern", i+1)
		}
		if s.Weight < 0 || math.IsInf(float64(s.Weight), 0) || math.IsNaN(float64(s.Weight)) {
			return fmt.Errorf("signature %q needs a non-negative, finite weight", s.Pattern)
		}
	}
	if cfg.Confidence < 0 || cfg.Confidence > 1 {
		return fmt.Errorf("confidence must be within [0, 1]")
	}
	if cfg.Version != nil {
		if cfg.Version.Group < 0 {
			return fmt.Errorf("version group must be >= 0")
		}
		if _, err := regexp.Compile(cfg.Version.Regex); err != nil {
			return fmt.Errorf("version regex: %w", err)
		}
	}
	return nil
}

// ExecuteFingerprintModule fetches the target and scores it against the weighted
// signatures, firing a single finding (with confidence and any version) once the
// score reaches the threshold. The boolean matcher engine is not involved.
func ExecuteFingerprintModule(ctx context.Context, target string, def *YAMLModule, opts Options) (*Result, error) {
	cfg := def.Fingerprint
	if cfg == nil {
		return nil, fmt.Errorf("no fingerprint configuration")
	}
	result := &Result{ModuleID: def.ID, Target: target, Findings: make([]Finding, 0)}

	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: opts.Timeout}
	}

	path := cfg.Path
	if path == "" {
		path = "/"
	}
	url := strings.TrimSuffix(target, "/") + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		// an unreachable target is simply no finding, not a module failure.
		return result, nil //nolint:nilerr // mirrors the http executor's swallow-per-request policy
	}
	defer resp.Body.Close()

	body, err := httpx.ReadCappedBody(resp)
	if err != nil {
		return result, nil //nolint:nilerr // a body read error yields no finding, same as above
	}
	bodyStr := string(body)

	score, version := scoreFingerprint(cfg, bodyStr, resp.Header)
	threshold := cfg.Confidence
	if threshold == 0 {
		threshold = defaultFingerprintConfidence
	}
	if score < threshold {
		return result, nil
	}

	finding := Finding{
		URL:        url,
		Severity:   def.Info.Severity,
		Evidence:   truncateEvidence(bodyStr),
		Confidence: score,
	}
	if version != "" {
		finding.Extracted = map[string]string{"version": version}
	}
	result.Findings = append(result.Findings, finding)
	return result, nil
}

// scoreFingerprint returns the matched fraction of signature weight and, when a
// version regex is set and the body matches, the captured version.
func scoreFingerprint(cfg *FingerprintConfig, body string, headers http.Header) (float32, string) {
	var matched, total float32
	for _, s := range cfg.Signatures {
		w := s.Weight
		if w == 0 {
			w = 1
		}
		total += w
		if s.Header {
			if headerContains(headers, s.Pattern) {
				matched += w
			}
		} else if strings.Contains(body, s.Pattern) {
			matched += w
		}
	}
	if total == 0 {
		return 0, ""
	}
	score := clampUnit(matched / total)

	version := ""
	if cfg.Version != nil && score > 0 {
		if re, err := regexp.Compile(cfg.Version.Regex); err == nil {
			if g := re.FindStringSubmatch(body); len(g) > cfg.Version.Group {
				version = g[cfg.Version.Group]
			}
		}
	}
	return score, version
}

// clampUnit bounds a fraction to [0, 1]. Weights are validated non-negative
// and finite at load time so this is a no-op on any real config; it only
// guards a caller that skips validation and feeds scoreFingerprint a
// negative or NaN weight. NaN needs its own check: every ordered comparison
// against NaN is false, so the < 0 and > 1 checks below would silently let
// it through otherwise.
func clampUnit(f float32) float32 {
	if math.IsNaN(float64(f)) {
		return 0
	}
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}

// headerContains reports whether pattern appears in any header name or value,
// case-insensitively, matching the framework detector's header semantics.
func headerContains(headers http.Header, pattern string) bool {
	p := strings.ToLower(pattern)
	for name, values := range headers {
		if strings.Contains(strings.ToLower(name), p) {
			return true
		}
		for _, v := range values {
			if strings.Contains(strings.ToLower(v), p) {
				return true
			}
		}
	}
	return false
}
