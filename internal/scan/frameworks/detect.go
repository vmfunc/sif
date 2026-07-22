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
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	charmlog "github.com/charmbracelet/log"
	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
)

// detectionThreshold is the minimum confidence for a detection to be reported.
const detectionThreshold = 0.5

// maxBodySize limits response body to prevent memory exhaustion.
const maxBodySize = 5 * 1024 * 1024

// detectionResult holds the result from a single detector.
type detectionResult struct {
	name       string
	confidence float32
	version    string
}

// loadCustomOnce loads the user signature directory the first time a scan runs,
// so config-defined detectors join the registry without a per-target re-read.
var loadCustomOnce sync.Once

// DetectFramework runs all registered detectors against the target URL.
func DetectFramework(url string, timeout time.Duration, logdir string) (*FrameworkResult, error) {
	loadCustomOnce.Do(loadCustomDetectors)

	log := output.Module("FRAMEWORK")
	log.Start()

	spin := output.NewSpinner("Detecting frameworks")
	spin.Start()

	client := httpx.Client(timeout)

	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, url, http.NoBody)
	if err != nil {
		spin.Stop()
		return nil, err
	}
	resp, err := client.Do(req) //nolint:bodyclose // closed via defer below
	if err != nil {
		spin.Stop()
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		spin.Stop()
		return nil, err
	}
	bodyStr := string(body)

	// Get all registered detectors
	detectors := GetDetectors()
	if len(detectors) == 0 {
		spin.Stop()
		log.Warn("No framework detectors registered")
		return nil, nil //nolint:nilnil // no detectors registered is not an error
	}

	// Run all detectors concurrently
	results := make(chan detectionResult, len(detectors))
	var wg sync.WaitGroup

	for _, detector := range detectors {
		wg.Add(1)
		go func(d Detector) {
			defer wg.Done()
			confidence, version := d.Detect(bodyStr, resp.Header)
			results <- detectionResult{
				name:       d.Name(),
				confidence: confidence,
				version:    version,
			}
		}(detector)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Find the best match
	// results arrive in goroutine-completion order; tie-break on name so the
	// winner is deterministic when two detectors land on the same confidence.
	var best detectionResult
	for r := range results {
		if r.confidence > best.confidence || (r.confidence == best.confidence && r.name < best.name) {
			best = r
		}
	}

	spin.Stop()

	if best.confidence <= detectionThreshold {
		log.Info("No framework detected with sufficient confidence")
		log.Complete(0, "detected")
		return nil, nil //nolint:nilnil // no framework detected is not an error
	}

	// Get version match details. the detector's own best.version is often
	// "unknown" (it only fingerprints the framework, not always the version),
	// while ExtractVersionOptimized digs the real version out of the body. prefer
	// that for both the reported version and the cve lookup, otherwise CVEs that
	// only match a concrete version are silently missed.
	versionMatch := ExtractVersionOptimized(bodyStr, best.name)
	version := resolveVersion(best.version, versionMatch.Version)
	cves, suggestions := getVulnerabilities(best.name, version)

	result := NewFrameworkResult(best.name, version, best.confidence, versionMatch.Confidence)
	result.WithVulnerabilities(cves, suggestions)

	// Log results
	if logdir != "" {
		logEntry := fmt.Sprintf("Detected framework: %s (version: %s, confidence: %.2f, version_confidence: %.2f)\n",
			best.name, version, best.confidence, versionMatch.Confidence)
		if len(cves) > 0 {
			logEntry += fmt.Sprintf("  Risk Level: %s\n", result.RiskLevel)
			logEntry += fmt.Sprintf("  CVEs: %v\n", cves)
			logEntry += fmt.Sprintf("  Recommendations: %v\n", suggestions)
		}
		_ = logger.Write(url, logdir, logEntry)
	}

	log.Success("Detected %s framework (version: %s, confidence: %.2f)",
		output.Highlight.Render(best.name), version, best.confidence)

	if versionMatch.Confidence > 0 {
		charmlog.Debugf("Version detected from: %s (confidence: %.2f)",
			versionMatch.Source, versionMatch.Confidence)
	}

	if len(cves) > 0 {
		log.Warn("Risk level: %s", output.SeverityHigh.Render(result.RiskLevel))
		for _, cve := range cves {
			log.Warn("Found potential vulnerability: %s", output.Highlight.Render(cve))
		}
		for _, suggestion := range suggestions {
			log.Info("Recommendation: %s", suggestion)
		}
	}

	log.Complete(1, "detected")

	return result, nil
}

// unknownVersion is the sentinel both detectors and the version extractor emit
// when no concrete version could be read from the response.
const unknownVersion = "unknown"

// resolveVersion picks the version to report and look CVEs up against. the
// detector's own value wins when it's concrete; otherwise we fall back to the
// version dug out of the body by ExtractVersionOptimized. either being
// "unknown"/empty means "no info", not a real version.
func resolveVersion(detectorVersion, extractedVersion string) string {
	if detectorVersion != "" && detectorVersion != unknownVersion {
		return detectorVersion
	}
	if extractedVersion != "" && extractedVersion != unknownVersion {
		return extractedVersion
	}
	return unknownVersion
}

// getVulnerabilities returns CVEs and recommendations for a framework version.
func getVulnerabilities(framework, version string) ([]string, []string) {
	entries, exists := knownCVEs[framework]
	if !exists {
		return nil, nil
	}

	var cves []string
	var recommendations []string
	seenRecs := make(map[string]bool)

	for _, entry := range entries {
		for _, affectedVer := range entry.AffectedVersions {
			if versionAffected(version, affectedVer) {
				cves = append(cves, fmt.Sprintf("%s (%s)", entry.CVE, entry.Severity))
				for _, rec := range entry.Recommendations {
					if !seenRecs[rec] {
						recommendations = append(recommendations, rec)
						seenRecs[rec] = true
					}
				}
				break
			}
		}
	}

	return cves, recommendations
}

// versionAffected reports whether version falls under an affected-version
// entry. matching is on dotted component boundaries in either direction, so
// "4.2" covers 4.2 and 4.2.1 but not 4.20, and a coarser version covers the
// listed sub-versions. the latter matters because some detectors only recover
// a bare major (Drupal's generator emits "10"); without it a bare major never
// matches a dotted affected entry and the CVE is silently missed.
func versionAffected(version, affected string) bool {
	return version == affected ||
		strings.HasPrefix(version, affected+".") ||
		strings.HasPrefix(affected, version+".")
}
