/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (Celeste Hickenlooper), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package frameworks

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	charmlog "github.com/charmbracelet/log"
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

// DetectFramework runs all registered detectors against the target URL.
func DetectFramework(url string, timeout time.Duration, logdir string) (*FrameworkResult, error) {
	log := output.Module("FRAMEWORK")
	log.Start()

	spin := output.NewSpinner("Detecting frameworks")
	spin.Start()

	client := &http.Client{Timeout: timeout}

	resp, err := client.Get(url)
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
		return nil, nil
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
	var best detectionResult
	for r := range results {
		if r.confidence > best.confidence {
			best = r
		}
	}

	spin.Stop()

	if best.confidence <= detectionThreshold {
		log.Info("No framework detected with sufficient confidence")
		log.Complete(0, "detected")
		return nil, nil
	}

	// Get version match details
	versionMatch := ExtractVersionOptimized(bodyStr, best.name)
	cves, suggestions := getVulnerabilities(best.name, best.version)

	result := NewFrameworkResult(best.name, best.version, best.confidence, versionMatch.Confidence)
	result.WithVulnerabilities(cves, suggestions)

	// Log results
	if logdir != "" {
		logEntry := fmt.Sprintf("Detected framework: %s (version: %s, confidence: %.2f, version_confidence: %.2f)\n",
			best.name, best.version, best.confidence, versionMatch.Confidence)
		if len(cves) > 0 {
			logEntry += fmt.Sprintf("  Risk Level: %s\n", result.RiskLevel)
			logEntry += fmt.Sprintf("  CVEs: %v\n", cves)
			logEntry += fmt.Sprintf("  Recommendations: %v\n", suggestions)
		}
		logger.Write(url, logdir, logEntry)
	}

	log.Success("Detected %s framework (version: %s, confidence: %.2f)",
		output.Highlight.Render(best.name), best.version, best.confidence)

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
			if version == affectedVer || hasPrefix(version, affectedVer) {
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

// hasPrefix is a simple prefix check without importing strings.
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
