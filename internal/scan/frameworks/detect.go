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
	"net/http"
	"sort"
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

// detectionResult holds the result from a single detector.
type detectionResult struct {
	name       string
	confidence float32
	version    string
}

// loadCustomOnce loads the user signature directory the first time a scan runs,
// so config-defined detectors join the registry without a per-target re-read.
var loadCustomOnce sync.Once

// gatherDetections fetches the target once and runs every registered detector
// against the response, returning each detector's raw confidence. it owns the
// spinner so the single- and multi-result entry points share one fetch. an
// empty result slice means no detectors were registered.
func gatherDetections(url string, timeout time.Duration) ([]detectionResult, string, error) {
	spin := output.NewSpinner("Detecting frameworks")
	spin.Start()
	defer spin.Stop()

	client := httpx.Client(timeout)

	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req) //nolint:bodyclose // closed via defer below
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := httpx.ReadCappedBody(resp)
	if err != nil {
		return nil, "", err
	}
	bodyStr := string(body)

	detectors := GetDetectors()
	if len(detectors) == 0 {
		return nil, bodyStr, nil
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

	out := make([]detectionResult, 0, len(detectors))
	for r := range results {
		out = append(out, r)
	}
	return out, bodyStr, nil
}

// DetectFramework runs all registered detectors against the target URL and
// returns the single highest-confidence match. see DetectFrameworks for the
// full set of detected technologies.
func DetectFramework(url string, timeout time.Duration, logdir string) (*FrameworkResult, error) {
	loadCustomOnce.Do(loadCustomDetectors)

	log := output.Module("FRAMEWORK")
	log.Start()

	results, bodyStr, err := gatherDetections(url, timeout)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		log.Warn("No framework detectors registered")
		return nil, nil //nolint:nilnil // no detectors registered is not an error
	}

	// Find the best match. tie-break on name so the winner is deterministic when
	// two detectors land on the same confidence.
	var best detectionResult
	for _, r := range results {
		if r.confidence > best.confidence || (r.confidence == best.confidence && r.name < best.name) {
			best = r
		}
	}

	if best.confidence <= detectionThreshold {
		log.Info("No framework detected with sufficient confidence")
		log.Complete(0, "detected")
		return nil, nil //nolint:nilnil // no framework detected is not an error
	}

	result := assembleResult(best, bodyStr, url, logdir, log)
	log.Complete(1, "detected")

	return result, nil
}

// DetectFrameworks runs all registered detectors and returns every framework
// that clears the detection threshold, ranked most-confident first. unlike
// DetectFramework it does not collapse to a single winner, so a page built from
// several technologies (say react behind a next.js server) reports each.
func DetectFrameworks(url string, timeout time.Duration, logdir string) ([]*FrameworkResult, error) {
	loadCustomOnce.Do(loadCustomDetectors)

	log := output.Module("FRAMEWORK")
	log.Start()

	results, bodyStr, err := gatherDetections(url, timeout)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		log.Warn("No framework detectors registered")
		return nil, nil //nolint:nilnil // no detectors registered is not an error
	}

	// keep everything above the threshold, most-confident first with a name
	// tie-break so the order is stable across runs.
	detected := make([]detectionResult, 0, len(results))
	for _, r := range results {
		if r.confidence > detectionThreshold {
			detected = append(detected, r)
		}
	}
	sort.Slice(detected, func(i, j int) bool {
		if detected[i].confidence != detected[j].confidence {
			return detected[i].confidence > detected[j].confidence
		}
		return detected[i].name < detected[j].name
	})

	if len(detected) == 0 {
		log.Info("No framework detected with sufficient confidence")
		log.Complete(0, "detected")
		return nil, nil //nolint:nilnil // no framework detected is not an error
	}

	out := make([]*FrameworkResult, 0, len(detected))
	for i := range detected {
		out = append(out, assembleResult(detected[i], bodyStr, url, logdir, log))
	}
	log.Complete(len(out), "detected")

	return out, nil
}

// assembleResult turns one detector hit into a full FrameworkResult: it digs out
// the concrete version, looks up CVEs for it, and logs the detection. the
// detector's own version is often "unknown" (it fingerprints the framework, not
// always the version), while ExtractVersionOptimized reads the real version from
// the body; prefer that for both the reported version and the cve lookup, else
// CVEs that only match a concrete version are silently missed.
func assembleResult(d detectionResult, bodyStr, url, logdir string, log *output.ModuleLogger) *FrameworkResult {
	versionMatch := ExtractVersionOptimized(bodyStr, d.name)
	version := resolveVersion(d.version, versionMatch.Version)
	cves, suggestions := getVulnerabilities(d.name, version)

	result := NewFrameworkResult(d.name, version, d.confidence, versionMatch.Confidence)
	result.WithVulnerabilities(cves, suggestions)

	if logdir != "" {
		logEntry := fmt.Sprintf("Detected framework: %s (version: %s, confidence: %.2f, version_confidence: %.2f)\n",
			d.name, version, d.confidence, versionMatch.Confidence)
		if len(cves) > 0 {
			logEntry += fmt.Sprintf("  Risk Level: %s\n", result.RiskLevel)
			logEntry += fmt.Sprintf("  CVEs: %v\n", cves)
			logEntry += fmt.Sprintf("  Recommendations: %v\n", suggestions)
		}
		_ = logger.Write(url, logdir, logEntry)
	}

	log.Success("Detected %s framework (version: %s, confidence: %.2f)",
		output.Highlight.Render(d.name), version, d.confidence)

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

	return result
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
