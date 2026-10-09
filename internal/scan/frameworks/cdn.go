/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2026 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

/*

   BSD 3-Clause License
   (c) 2022-2026 vmfunc, xyzeva & contributors

*/

package frameworks

import (
	"net/http"
	"sync"
)

// cdnRegistry holds CDN/hosting/edge detectors, kept separate from registry
// (see detector.go) because a CDN/edge is orthogonal to an application
// framework: a target can be both Cloudflare-fronted and Next.js. DetectFramework
// takes a single global-argmax winner, so a CDN detector in registry would
// outrank the real framework (a bare cf-ray header scores ~0.999 via
// sigmoidConfidence) and report "Cloudflare" instead of "Next.js". A separate
// registry reduced by its own DetectCDN lets both answers coexist.
var (
	cdnRegistryMu sync.RWMutex
	cdnRegistry   = make(map[string]Detector)
)

// RegisterCDN adds a CDN/hosting detector. should be called from init().
func RegisterCDN(d Detector) {
	cdnRegistryMu.Lock()
	defer cdnRegistryMu.Unlock()
	cdnRegistry[d.Name()] = d
}

// GetCDNDetectors returns all registered CDN/hosting detectors.
func GetCDNDetectors() map[string]Detector {
	cdnRegistryMu.RLock()
	defer cdnRegistryMu.RUnlock()

	result := make(map[string]Detector, len(cdnRegistry))
	for k, v := range cdnRegistry {
		result[k] = v
	}
	return result
}

// cdnDetectionThreshold mirrors detectionThreshold in detect.go: below this,
// report no CDN rather than a weak guess.
const cdnDetectionThreshold = 0.5

// CDNResult is CDN/hosting-provider detection output. It is a separate type from
// FrameworkResult because the two come from independent pools and either can be
// absent while the other is present.
type CDNResult struct {
	Name       string  `json:"name"`
	Confidence float32 `json:"confidence"`
}

// ResultType implements the ScanResult interface.
func (r *CDNResult) ResultType() string { return "cdn" }

// DetectCDN runs every registered CDN/hosting detector against an already-fetched
// response and returns the best match, or nil below cdnDetectionThreshold. Unlike
// DetectFramework it takes body/headers directly, so a caller with a response in
// hand can run both detections off one request.
func DetectCDN(body string, headers http.Header) *CDNResult {
	detectors := GetCDNDetectors()
	if len(detectors) == 0 {
		return nil
	}

	var best CDNResult
	for _, d := range detectors {
		confidence, _ := d.Detect(body, headers)
		if confidence > best.Confidence || (confidence == best.Confidence && confidence > 0 && d.Name() < best.Name) {
			best = CDNResult{Name: d.Name(), Confidence: confidence}
		}
	}

	if best.Confidence <= cdnDetectionThreshold {
		return nil
	}
	return &best
}
