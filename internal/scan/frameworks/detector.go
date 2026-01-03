/*

   BSD 3-Clause License
   (c) 2022-2025 vmfunc, xyzeva & contributors

*/

package frameworks

import (
	"net/http"
	"strings"
	"sync"
)

// Signature represents a pattern to match for framework detection.
type Signature struct {
	Pattern    string
	Weight     float32
	HeaderOnly bool
}

// Detector is the interface for framework detection plugins.
type Detector interface {
	// Name returns the unique framework name.
	Name() string
	// Signatures returns patterns to search for this framework.
	Signatures() []Signature
	// Detect performs detection and returns confidence (0.0-1.0) and version.
	// The version can be empty if not detectable.
	Detect(body string, headers http.Header) (confidence float32, version string)
}

// registry holds all registered detectors.
var (
	registryMu sync.RWMutex
	registry   = make(map[string]Detector)
)

// Register adds a detector to the registry. Should be called from init().
func Register(d Detector) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[d.Name()] = d
}

// GetDetectors returns all registered detectors.
func GetDetectors() map[string]Detector {
	registryMu.RLock()
	defer registryMu.RUnlock()

	// Return a copy to prevent mutation
	result := make(map[string]Detector, len(registry))
	for k, v := range registry {
		result[k] = v
	}
	return result
}

// GetDetector returns a specific detector by name.
func GetDetector(name string) (Detector, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	d, ok := registry[name]
	return d, ok
}

// BaseDetector provides common functionality for detector implementations.
type BaseDetector struct {
	name       string
	signatures []Signature
}

// NewBaseDetector creates a new base detector.
func NewBaseDetector(name string, signatures []Signature) BaseDetector {
	return BaseDetector{name: name, signatures: signatures}
}

// Name returns the framework name.
func (b BaseDetector) Name() string {
	return b.name
}

// Signatures returns the detection signatures.
func (b BaseDetector) Signatures() []Signature {
	return b.signatures
}

// MatchSignatures checks body and headers against signatures and returns a weighted score.
func (b BaseDetector) MatchSignatures(body string, headers http.Header) float32 {
	var weightedScore float32
	var totalWeight float32

	for _, sig := range b.signatures {
		totalWeight += sig.Weight

		if sig.HeaderOnly {
			if containsHeader(headers, sig.Pattern) {
				weightedScore += sig.Weight
			}
		} else if strings.Contains(body, sig.Pattern) {
			weightedScore += sig.Weight
		}
	}

	if totalWeight == 0 {
		return 0
	}

	return weightedScore / totalWeight
}

// containsHeader checks if a signature pattern exists in headers.
func containsHeader(headers http.Header, signature string) bool {
	sigLower := strings.ToLower(signature)

	// Check header names
	for name := range headers {
		if strings.Contains(strings.ToLower(name), sigLower) {
			return true
		}
	}

	// Check header values
	for _, values := range headers {
		for _, value := range values {
			if strings.Contains(strings.ToLower(value), sigLower) {
				return true
			}
		}
	}
	return false
}
