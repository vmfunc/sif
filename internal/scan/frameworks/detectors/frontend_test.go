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

package detectors

import (
	"net/http"
	"testing"

	fw "github.com/vmfunc/sif/internal/scan/frameworks"
)

func TestFrontendLibDetectors_Positive(t *testing.T) {
	tests := []struct {
		name     string
		detector fw.Detector
		body     string
	}{
		{"Alpine x-data only", &alpineDetector{}, `<div x-data="{ open: false }"><span x-text="open"></span></div>`},
		{"Alpine cdn plus cloak", &alpineDetector{}, `<script src="//unpkg.com/alpinejs@3.13.0/dist/cdn.min.js" defer></script><div x-cloak></div>`},
		{"Qwik container only", &qwikDetector{}, `<html q:container="resumable" lang="en">`},
		{"Qwik bootstrap", &qwikDetector{}, `<html q:container="paused" q:version="1.5.0" q:base="/build/"><script>qwikloader</script>`},
		{"jQuery cdn", &jqueryDetector{}, `<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>`},
		{"jQuery googleapis", &jqueryDetector{}, `<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>`},
		{"jQuery wp bundled", &jqueryDetector{}, `<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>`},
		{"Livewire component", &livewireDetector{}, `<div wire:id="aZ19" wire:snapshot="{&quot;data&quot;:[]}"><input wire:model="name"></div>`},
		{"Stimulus controller", &stimulusDetector{}, `<div data-controller="hello" data-action="click->hello#greet"><button>x</button></div>`},
		{"Turbo frame", &turboDetector{}, `<turbo-frame id="messages"><a href="/x" data-turbo="true">x</a></turbo-frame>`},
		{"Turbo track only", &turboDetector{}, `<link rel="stylesheet" href="/app.css" data-turbo-track="reload">`},
		{"Knockout bindings", &knockoutDetector{}, `<span data-bind="text: name"></span><script>ko.applyBindings(vm);</script>`},
		{"Unpoly script", &unpolyDetector{}, `<script src="https://unpkg.com/unpoly@3.7.0/unpoly.min.js"></script>`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, _ := tt.detector.Detect(tt.body, http.Header{})
			if conf <= 0.5 {
				t.Errorf("%s: confidence = %.3f, want > 0.5", tt.name, conf)
			}
		})
	}
}

func TestFrontendLibDetectors_Negative(t *testing.T) {
	tests := []struct {
		name     string
		detector fw.Detector
		body     string
	}{
		{"Alpine prose", &alpineDetector{}, `<meta property="og:title" content="Alpine.js guide"><p>Alpine.js is a lightweight framework.</p>`},
		{"Vue at-click not Alpine", &alpineDetector{}, `<div id="app" @click="toggle"><button :class="x">go</button></div>`},
		{"Alpine max-data substring", &alpineDetector{}, `<table class="max-data-grid" id="webflux-data">x</table>`},
		{"Qwik prose", &qwikDetector{}, `<p>Qwik is a resumable framework, see qwik.dev for details.</p>`},
		{"jQuery prose", &jqueryDetector{}, `<meta property="og:title" content="We dropped jquery"><p>migrating off jquery this year.</p>`},
		{"Livewire single directive", &livewireDetector{}, `<button wire:click="save">save</button>`},
		{"Livewire prose", &livewireDetector{}, `<p>Livewire is a full-stack framework for Laravel.</p>`},
		{"Stimulus prose", &stimulusDetector{}, `<p>Stimulus is a modest JavaScript framework for the HTML you already have.</p>`},
		{"Stimulus generic data-action", &stimulusDetector{}, `<button data-action="add-to-cart" class="buy">Buy now</button>`},
		{"Turbo prose og", &turboDetector{}, `<meta property="og:title" content="Turbo accelerates Rails"><p>Turbo Drive is great.</p>`},
		{"Turbo vs legacy turbolinks", &turboDetector{}, `<link rel="stylesheet" href="/app.css" data-turbolinks-track="reload">`},
		{"Knockout prose", &knockoutDetector{}, `<p>Knockout.js is an MVVM library for JavaScript.</p>`},
		{"Unpoly attr substring collision", &unpolyDetector{}, `<div data-controller="popup" data-popup-target="menu" class="sign-up-target back-up-layer">x</div>`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, _ := tt.detector.Detect(tt.body, http.Header{})
			if conf > 0.5 {
				t.Errorf("%s: confidence = %.3f, want <= 0.5", tt.name, conf)
			}
		})
	}
}

func TestFrontendLibDetectors_Version(t *testing.T) {
	tests := []struct {
		name     string
		detector fw.Detector
		body     string
		want     string
	}{
		{"jQuery filename", &jqueryDetector{}, `<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>`, "3.6.0"},
		{"jQuery googleapis path", &jqueryDetector{}, `<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>`, "3.7.1"},
		{"Alpine cdn", &alpineDetector{}, `<div x-data></div><script src="//unpkg.com/alpinejs@3.13.0/dist/cdn.min.js"></script>`, "3.13.0"},
		{"Qwik attr", &qwikDetector{}, `<html q:container="paused" q:version="1.5.0">`, "1.5.0"},
		{"Knockout filename", &knockoutDetector{}, `<span data-bind="x"></span><script src="/js/knockout-3.5.1.js"></script>`, "3.5.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, version := tt.detector.Detect(tt.body, http.Header{})
			if version != tt.want {
				t.Errorf("%s: version = %q, want %q", tt.name, version, tt.want)
			}
		})
	}
}
