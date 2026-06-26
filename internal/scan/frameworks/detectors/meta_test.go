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

func TestSiteGeneratorDetectors_Positive(t *testing.T) {
	tests := []struct {
		name     string
		detector fw.Detector
		body     string
	}{
		{"Hugo minified", &hugoDetector{}, `<meta name=generator content="Hugo 0.163.3"><title>x</title>`},
		{"Jekyll", &jekyllDetector{}, `<meta name="generator" content="Jekyll v4.4.1" />`},
		{"Docusaurus minified", &docusaurusDetector{}, `<head><meta charset=UTF-8><meta name=generator content="Docusaurus v3.10.1">`},
		{"MkDocs Material", &mkdocsDetector{}, `<meta name=generator content="mkdocs-1.6.1, mkdocs-material-9.7.0">`},
		{"Eleventy default", &eleventyDetector{}, `<meta name="generator" content="Eleventy v3.0.0">`},
		{"Eleventy custom label", &eleventyDetector{}, `<meta name="generator" content="Eleventy (Build Awesome) v4.0.0" />`},
		{"Hexo", &hexoDetector{}, `<meta name="generator" content="Hexo 8.1.1">`},
		{"VuePress", &vuepressDetector{}, `<meta name="generator" content="VuePress 2.0.0-rc.26" />`},
		{"Sphinx assets", &sphinxDetector{}, `<script src="_static/documentation_options.js"></script><script src="_static/doctools.js"></script>`},
		{"Nikola", &nikolaDetector{}, `<meta name="generator" content="Nikola (getnikola.com)">`},
		{"Publii", &publiiDetector{}, `<meta name="generator" content="Publii Open-Source CMS for Static Site">`},
		{"Remix context", &remixDetector{}, `<script>window.__remixContext = {"state":{}};</script>`},
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

func TestSiteGeneratorDetectors_Negative(t *testing.T) {
	tests := []struct {
		name     string
		detector fw.Detector
		body     string
	}{
		{"Hugo Boss", &hugoDetector{}, `<meta property="og:title" content="Hugo Boss SS26"><p>Hugo is a designer.</p>`},
		{"Jekyll novel", &jekyllDetector{}, `<meta property="og:title" content="Jekyll and Hyde">`},
		{"Docusaurus tutorial", &docusaurusDetector{}, `<meta property="og:title" content="Docusaurus Tutorial">`},
		{"Docusaurus brand og", &docusaurusDetector{}, `<meta property="og:title" content="Docusaurus">`},
		{"MkDocs guide", &mkdocsDetector{}, `<meta property="og:title" content="MkDocs Guide"><p>MkDocs is great.</p>`},
		{"plain migration prose", &hugoDetector{}, `<p>We migrated from Jekyll to Hugo last year.</p>`},
		{"Eleventy brand og", &eleventyDetector{}, `<meta property="og:title" content="Eleventy">`},
		{"Hexo brand og", &hexoDetector{}, `<meta property="og:title" content="Hexo">`},
		{"VuePress release prose", &vuepressDetector{}, `<meta property="og:title" content="VuePress 2 Released">`},
		{"Sphinx link only", &sphinxDetector{}, `<p>Built with <a href="https://www.sphinx-doc.org">Sphinx</a>.</p>`},
		{"Sphinx doctools only", &sphinxDetector{}, `<script src="_static/doctools.js"></script>`},
		{"Nikola Tesla og", &nikolaDetector{}, `<meta property="og:title" content="Nikola Tesla biography">`},
		{"Publii brand og", &publiiDetector{}, `<meta property="og:title" content="Publii">`},
		{"Remix audio asset", &remixDetector{}, `<audio src="/audio/track_remix.mp3"></audio>`},
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

func TestSiteGeneratorDetectors_Version(t *testing.T) {
	tests := []struct {
		name     string
		detector fw.Detector
		body     string
		want     string
	}{
		{"Hugo", &hugoDetector{}, `<meta name=generator content="Hugo 0.163.3">`, "0.163.3"},
		{"Jekyll", &jekyllDetector{}, `<meta name="generator" content="Jekyll v4.4.1" />`, "4.4.1"},
		{"Docusaurus", &docusaurusDetector{}, `<meta name=generator content="Docusaurus v3.10.1">`, "3.10.1"},
		{"MkDocs", &mkdocsDetector{}, `<meta name=generator content="mkdocs-1.6.1, mkdocs-material-9.7.0">`, "1.6.1"},
		{"Eleventy", &eleventyDetector{}, `<meta name="generator" content="Eleventy v3.0.0">`, "3.0.0"},
		{"Eleventy custom label", &eleventyDetector{}, `<meta name="generator" content="Eleventy (Build Awesome) v4.0.0">`, "4.0.0"},
		{"Hexo", &hexoDetector{}, `<meta name="generator" content="Hexo 8.1.1">`, "8.1.1"},
		{"VuePress", &vuepressDetector{}, `<meta name="generator" content="VuePress 2.0.0-rc.26">`, "2.0.0"},
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
