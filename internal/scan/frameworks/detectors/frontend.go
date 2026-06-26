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
	fw.Register(&htmxDetector{})
	fw.Register(&alpineDetector{})
	fw.Register(&jqueryDetector{})
	fw.Register(&knockoutDetector{})
	fw.Register(&livewireDetector{})
	fw.Register(&qwikDetector{})
	fw.Register(&stimulusDetector{})
	fw.Register(&turboDetector{})
	fw.Register(&unpolyDetector{})
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
		// require the attribute-assignment form, not the bare word, so prose
		// discussing ng-version can't match; weighted to clear the threshold alone.
		{Pattern: `ng-version="`, Weight: 1.2},
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
	// "svelte-" alone cleared the detection threshold on prose merely naming a
	// package (svelte-native, svelte-check). the remaining patterns only show
	// up in an actual svelte bundle.
	return []fw.Signature{
		{Pattern: "__svelte", Weight: 0.5},
		{Pattern: "svelte/internal", Weight: 0.4},
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
		{Pattern: "ember-application", Weight: 0.5},
		{Pattern: "ember-view", Weight: 0.4},
		{Pattern: "ember.js", Weight: 0.4},
		{Pattern: "ember.min.js", Weight: 0.4},
		{Pattern: "ember-cli", Weight: 0.3},
		{Pattern: `id="ember`, Weight: 0.4},
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
		{Pattern: "Backbone.Model", Weight: 0.4},
		{Pattern: "Backbone.View", Weight: 0.4},
		{Pattern: "Backbone.Router", Weight: 0.4},
		{Pattern: "backbone.js", Weight: 0.4},
		{Pattern: "backbone-min.js", Weight: 0.4},
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

// htmxDetector detects the htmx library.
type htmxDetector struct{}

func (d *htmxDetector) Name() string { return "htmx" }

func (d *htmxDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "hx-get", Weight: 0.5},
		{Pattern: "hx-post", Weight: 0.5},
		{Pattern: "hx-swap", Weight: 0.4},
		{Pattern: "hx-target", Weight: 0.4},
		{Pattern: "hx-boost", Weight: 0.4},
		{Pattern: "htmx.org", Weight: 0.5},
	}
}

func (d *htmxDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// alpineDetector detects Alpine.js.
type alpineDetector struct{}

func (d *alpineDetector) Name() string { return "Alpine.js" }

func (d *alpineDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: " x-data", Weight: 0.6},
		{Pattern: "alpinejs", Weight: 0.5},
		{Pattern: "x-cloak", Weight: 0.4},
		{Pattern: "x-transition", Weight: 0.4},
	}
}

func (d *alpineDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// qwikDetector detects the Qwik framework.
type qwikDetector struct{}

func (d *qwikDetector) Name() string { return "Qwik" }

func (d *qwikDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "q:container", Weight: 0.5},
		{Pattern: "q:version", Weight: 0.4},
		{Pattern: "q:base", Weight: 0.3},
		{Pattern: "qwikloader", Weight: 0.3},
	}
}

func (d *qwikDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// jqueryDetector detects the jQuery library.
type jqueryDetector struct{}

func (d *jqueryDetector) Name() string { return "jQuery" }

func (d *jqueryDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "jquery.min.js", Weight: 0.5},
		{Pattern: "jquery-", Weight: 0.5},
		{Pattern: "jQuery.fn.jquery", Weight: 0.4},
	}
}

func (d *jqueryDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// livewireDetector detects Laravel Livewire.
type livewireDetector struct{}

func (d *livewireDetector) Name() string { return "Livewire" }

func (d *livewireDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "wire:id", Weight: 0.5},
		{Pattern: "wire:snapshot", Weight: 0.4},
		{Pattern: "wire:model", Weight: 0.4},
		{Pattern: "wire:click", Weight: 0.4},
	}
}

func (d *livewireDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// stimulusDetector detects the Stimulus controller framework (part of Hotwire, the Rails 7 default).
type stimulusDetector struct{}

func (d *stimulusDetector) Name() string { return "Stimulus" }

func (d *stimulusDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "data-controller=", Weight: 0.5},
		{Pattern: "data-action=", Weight: 0.3},
		{Pattern: "@hotwired/stimulus", Weight: 0.4},
	}
}

func (d *stimulusDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// turboDetector detects Turbo (part of Hotwire, the Rails 7 default).
type turboDetector struct{}

func (d *turboDetector) Name() string { return "Turbo" }

func (d *turboDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "<turbo-frame", Weight: 0.5},
		{Pattern: "data-turbo-", Weight: 0.5},
		{Pattern: "@hotwired/turbo", Weight: 0.5},
	}
}

func (d *turboDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// knockoutDetector detects Knockout.js.
type knockoutDetector struct{}

func (d *knockoutDetector) Name() string { return "Knockout.js" }

func (d *knockoutDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "data-bind=", Weight: 0.5},
		{Pattern: "ko.applyBindings", Weight: 0.5},
		{Pattern: "knockout-", Weight: 0.4},
	}
}

func (d *knockoutDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// unpolyDetector detects the Unpoly library.
type unpolyDetector struct{}

func (d *unpolyDetector) Name() string { return "Unpoly" }

func (d *unpolyDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "unpoly.min.js", Weight: 0.5},
		{Pattern: "unpoly.js", Weight: 0.4},
		{Pattern: "unpoly@", Weight: 0.4},
	}
}

func (d *unpolyDetector) Detect(body string, headers http.Header) (float32, string) {
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
		{Pattern: "__meteor_runtime_config__", Weight: 0.6},
		{Pattern: "Meteor.startup", Weight: 0.3},
		{Pattern: "/packages/meteor", Weight: 0.3},
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
