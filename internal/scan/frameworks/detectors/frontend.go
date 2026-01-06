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

/*

   BSD 3-Clause License
   (c) 2022-2025 vmfunc, xyzeva & contributors

*/

package detectors

import (
	"net/http"

	fw "github.com/vmfunc/sif/internal/scan/frameworks"
)

func init() {
	// Register all frontend detectors
	fw.Register(&reactDetector{})
	fw.Register(&vueDetector{})
	fw.Register(&angularDetector{})
	fw.Register(&svelteDetector{})
	fw.Register(&emberDetector{})
	fw.Register(&backboneDetector{})
	fw.Register(&meteorDetector{})
}

// reactDetector detects React framework.
type reactDetector struct{}

func (d *reactDetector) Name() string { return "React" }

func (d *reactDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "data-reactroot", Weight: 0.5},
		{Pattern: "react-dom", Weight: 0.4},
		{Pattern: "__REACT_DEVTOOLS", Weight: 0.4},
		{Pattern: "react.production", Weight: 0.4},
		{Pattern: "_reactRootContainer", Weight: 0.3},
	}
}

func (d *reactDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// vueDetector detects Vue.js framework.
type vueDetector struct{}

func (d *vueDetector) Name() string { return "Vue.js" }

func (d *vueDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "data-v-", Weight: 0.5},
		{Pattern: "Vue.js", Weight: 0.4},
		{Pattern: "vue.runtime", Weight: 0.4},
		{Pattern: "vue.min.js", Weight: 0.4},
		{Pattern: "__vue__", Weight: 0.3},
		{Pattern: "v-cloak", Weight: 0.3},
	}
}

func (d *vueDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// angularDetector detects Angular framework.
type angularDetector struct{}

func (d *angularDetector) Name() string { return "Angular" }

func (d *angularDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "ng-version", Weight: 0.5},
		{Pattern: "ng-app", Weight: 0.4},
		{Pattern: "ng-controller", Weight: 0.4},
		{Pattern: "angular.js", Weight: 0.4},
		{Pattern: "angular.min.js", Weight: 0.4},
		{Pattern: "ng-binding", Weight: 0.3},
		{Pattern: "_nghost", Weight: 0.3},
		{Pattern: "_ngcontent", Weight: 0.3},
	}
}

func (d *angularDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// svelteDetector detects Svelte framework.
type svelteDetector struct{}

func (d *svelteDetector) Name() string { return "Svelte" }

func (d *svelteDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "svelte", Weight: 0.4},
		{Pattern: "__svelte", Weight: 0.5},
		{Pattern: "svelte-", Weight: 0.3},
	}
}

func (d *svelteDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// emberDetector detects Ember.js framework.
type emberDetector struct{}

func (d *emberDetector) Name() string { return "Ember.js" }

func (d *emberDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "ember", Weight: 0.4},
		{Pattern: "ember-cli", Weight: 0.4},
		{Pattern: "data-ember", Weight: 0.3},
	}
}

func (d *emberDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// backboneDetector detects Backbone.js framework.
type backboneDetector struct{}

func (d *backboneDetector) Name() string { return "Backbone.js" }

func (d *backboneDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "backbone", Weight: 0.4},
		{Pattern: "Backbone.", Weight: 0.4},
	}
}

func (d *backboneDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// meteorDetector detects Meteor framework.
type meteorDetector struct{}

func (d *meteorDetector) Name() string { return "Meteor" }

func (d *meteorDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "__meteor_runtime_config__", Weight: 0.5},
		{Pattern: "meteor", Weight: 0.3},
	}
}

func (d *meteorDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}
