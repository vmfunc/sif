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
	"net/http"
	"regexp"
	"strings"
	"unicode"
)

// VersionMatch represents a version detection result with confidence.
type VersionMatch struct {
	Version    string
	Confidence float32
	Source     string // where the version was found
}

// compiledVersionPattern holds a pre-compiled regex for version extraction
type compiledVersionPattern struct {
	re         *regexp.Regexp
	confidence float32
	source     string
}

// frameworkVersionPatterns maps framework names to their pre-compiled version patterns.
// Patterns are compiled once at package initialization for optimal performance.
var frameworkVersionPatterns map[string][]compiledVersionPattern

func init() {
	// Raw patterns to be compiled
	rawPatterns := map[string][]struct {
		pattern    string
		confidence float32
		source     string
	}{
		"Laravel": {
			{`Laravel\s+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
		},
		"Django": {
			{`Django[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
		},
		"Ruby on Rails": {
			{`Rails[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
		},
		"Express.js": {
			{`Express[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`"express":\s*"[~^]?(\d+\.\d+(?:\.\d+)?)"`, 0.85, "package.json"},
		},
		"ASP.NET": {
			// header names are matched case-insensitively: Go's http.Header
			// canonicalizes "X-AspNet-Version" to "X-Aspnet-Version", so a
			// case-sensitive literal here would never match the header line
			// built by headerSearchText.
			{`(?i:X-AspNet-Version):\s*(\d+\.\d+(?:\.\d+)?)`, 0.95, "header"},
			{`ASP\.NET[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`(?i:X-AspNetMvc-Version):\s*(\d+\.\d+(?:\.\d+)?)`, 0.9, "MVC header"},
		},
		"ASP.NET Core": {
			{`\.NET\s*(\d+\.\d+(?:\.\d+)?)`, 0.8, "dotnet version"},
		},
		"Spring": {
			{`Spring[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
		},
		"Flask": {
			{`Flask[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`Werkzeug[/\s]+(\d+\.\d+(?:\.\d+)?)`, 0.7, "werkzeug version"},
		},
		"Next.js": {
			{`Next\.js[/\s]+[Vv]?(\d{1,2}\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`"next":\s*"[~^]?(\d{1,2}\.\d+(?:\.\d+)?)"`, 0.85, "package.json"},
		},
		"Nuxt.js": {
			{`Nuxt[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`"nuxt":\s*"[~^]?(\d+\.\d+(?:\.\d+)?)"`, 0.85, "package.json"},
		},
		"Vue.js": {
			{`Vue\.js[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`"vue":\s*"[~^]?(\d+\.\d+(?:\.\d+)?)"`, 0.85, "package.json"},
			{`vue@(\d+\.\d+(?:\.\d+)?)`, 0.8, "CDN reference"},
		},
		"Angular": {
			{`ng-version="(\d+\.\d+(?:\.\d+)?)"`, 0.95, "ng-version attribute"},
			{`Angular[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`"@angular/core":\s*"[~^]?(\d+\.\d+(?:\.\d+)?)"`, 0.85, "package.json"},
		},
		"React": {
			{`React[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`"react":\s*"[~^]?(\d+\.\d+(?:\.\d+)?)"`, 0.85, "package.json"},
			{`react@(\d+\.\d+(?:\.\d+)?)`, 0.8, "CDN reference"},
		},
		"Svelte": {
			{`Svelte[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`"svelte":\s*"[~^]?(\d+\.\d+(?:\.\d+)?)"`, 0.85, "package.json"},
		},
		"SvelteKit": {
			{`"@sveltejs/kit":\s*"[~^]?(\d+\.\d+(?:\.\d+)?)"`, 0.85, "package.json"},
		},
		"htmx": {
			{`htmx(?:\.org)?@(\d+\.\d+(?:\.\d+)?)`, 0.85, "CDN reference"},
			{`"htmx\.org":\s*"[~^]?(\d+\.\d+(?:\.\d+)?)"`, 0.85, "package.json"},
		},
		"WordPress": {
			{`<meta name="generator" content="WordPress (\d+\.\d+(?:\.\d+)?)"`, 0.95, "generator meta"},
			{`WordPress (\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
		},
		"Drupal": {
			{`Drupal[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`<meta name="Generator" content="Drupal (\d+)`, 0.9, "generator meta"},
		},
		"Joomla": {
			{`Joomla[!/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`<meta name="generator" content="Joomla! - Open Source Content Management - Version (\d+\.\d+(?:\.\d+)?)"`, 0.95, "generator meta"},
		},
		"Magento": {
			{`Magento[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
		},
		"Symfony": {
			{`Symfony[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
		},
		"Phoenix": {
			{`Phoenix[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
		},
		"Ember.js": {
			{`Ember[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
		},
		"Backbone.js": {
			{`Backbone[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
		},
		"Meteor": {
			{`Meteor[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
		},
		"Ghost": {
			{`Ghost[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
		},
		"Astro": {
			{`<meta name="generator" content="Astro v?(\d+\.\d+(?:\.\d+)?)"`, 0.95, "generator meta"},
			{`Astro[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`"astro":\s*"[~^]?(\d+\.\d+(?:\.\d+)?)"`, 0.85, "package.json"},
		},
		"Hugo": {
			{`content="Hugo (\d+\.\d+(?:\.\d+)?)`, 0.95, "generator meta"},
		},
		"Jekyll": {
			{`content="Jekyll v(\d+\.\d+(?:\.\d+)?)`, 0.95, "generator meta"},
		},
		"Docusaurus": {
			{`content="Docusaurus v(\d+\.\d+(?:\.\d+)?)`, 0.95, "generator meta"},
		},
		"MkDocs": {
			{`content="mkdocs-(\d+\.\d+(?:\.\d+)?)`, 0.9, "generator meta"},
		},
		"TYPO3": {
			{`content="TYPO3 (\d+\.\d+(?:\.\d+)?)`, 0.9, "generator meta"},
		},
		"Eleventy": {
			{`content="Eleventy[^"]*?v(\d+\.\d+(?:\.\d+)?)`, 0.9, "generator meta"},
		},
		"Hexo": {
			{`content="Hexo (\d+\.\d+(?:\.\d+)?)`, 0.9, "generator meta"},
		},
		"VuePress": {
			{`content="VuePress (\d+\.\d+(?:\.\d+)?)`, 0.9, "generator meta"},
		},
		"jQuery": {
			{`jquery-(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js`, 0.9, "script filename"},
			{`jquery@(\d+\.\d+(?:\.\d+)?)`, 0.85, "CDN reference"},
			{`/jquery/(\d+\.\d+(?:\.\d+)?)/`, 0.85, "CDN path"},
			{`jQuery v(\d+\.\d+(?:\.\d+)?)`, 0.9, "library banner"},
		},
		"Alpine.js": {
			{`alpinejs@(\d+\.\d+(?:\.\d+)?)`, 0.85, "CDN reference"},
		},
		"Qwik": {
			{`q:version="(\d+\.\d+(?:\.\d+)?)"`, 0.9, "container attribute"},
		},
		"MediaWiki": {
			{`content="MediaWiki (\d+\.\d+(?:\.\d+)?)`, 0.9, "generator meta"},
		},
		"Discourse": {
			{`content="Discourse (\d+\.\d+(?:\.\d+)?)`, 0.9, "generator meta"},
		},
		"Knockout.js": {
			{`knockout-(\d+\.\d+(?:\.\d+)?)`, 0.9, "script filename"},
		},
	}

	// Compile all patterns
	frameworkVersionPatterns = make(map[string][]compiledVersionPattern, len(rawPatterns))
	for framework, patterns := range rawPatterns {
		compiled := make([]compiledVersionPattern, len(patterns))
		for i, p := range patterns {
			compiled[i] = compiledVersionPattern{
				re:         regexp.MustCompile(p.pattern),
				confidence: p.confidence,
				source:     p.source,
			}
		}
		frameworkVersionPatterns[framework] = compiled
	}
}

// ExtractVersionOptimized extracts version using pre-compiled patterns,
// searching only the response body. This is exported for use by individual
// detector implementations.
func ExtractVersionOptimized(body string, framework string) VersionMatch {
	return extractVersion(body, framework)
}

// ExtractVersionFromResponse is like ExtractVersionOptimized but also searches
// canonical header lines, so header-shaped patterns (e.g. ASP.NET's
// X-AspNet-Version) can match; use it for detectors with header-shaped patterns.
func ExtractVersionFromResponse(body string, headers http.Header, framework string) VersionMatch {
	return extractVersion(body+"\n"+headerSearchText(headers), framework)
}

// headerSearchText renders headers as canonical "Name: value" lines, one per
// value, so version regexes written against raw header text (e.g.
// "X-AspNet-Version: 4.0.30319") have something to match against.
func headerSearchText(headers http.Header) string {
	var b strings.Builder
	for name, values := range headers {
		for _, v := range values {
			b.WriteString(name)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// extractVersion runs every pattern registered for framework against text and
// keeps the highest-confidence valid match.
func extractVersion(text string, framework string) VersionMatch {
	patterns, exists := frameworkVersionPatterns[framework]
	if !exists {
		return VersionMatch{Version: "unknown", Confidence: 0, Source: ""}
	}

	var bestMatch VersionMatch
	for _, p := range patterns {
		matches := p.re.FindStringSubmatch(text)
		if len(matches) > 1 && p.confidence > bestMatch.Confidence {
			candidate := matches[1]
			if isValidVersionString(candidate) {
				bestMatch = VersionMatch{
					Version:    candidate,
					Confidence: p.confidence,
					Source:     p.source,
				}
			}
		}
	}

	if bestMatch.Version == "" {
		return VersionMatch{Version: "unknown", Confidence: 0, Source: ""}
	}
	return bestMatch
}

// isValidVersionString checks if a version string is digits and dots only, with
// at most three dots.
func isValidVersionString(v string) bool {
	if v == "" || len(v) > 20 {
		return false
	}

	dotCount := 0
	digitCount := 0
	for _, c := range v {
		switch {
		case c == '.':
			dotCount++
			if dotCount > 3 {
				return false
			}
		case unicode.IsDigit(c):
			digitCount++
		default:
			return false
		}
	}
	return digitCount > 0
}
