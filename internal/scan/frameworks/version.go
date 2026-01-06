/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (vmfunc), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package frameworks

import (
	"regexp"
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
			{`laravel/framework.*?(\d+\.\d+(?:\.\d+)?)`, 0.8, "composer.json"},
		},
		"Django": {
			{`Django[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`django.*?(\d+\.\d+(?:\.\d+)?)`, 0.7, "package reference"},
		},
		"Ruby on Rails": {
			{`Rails[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`rails.*?(\d+\.\d+(?:\.\d+)?)`, 0.7, "gem reference"},
		},
		"Express.js": {
			{`Express[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`"express":\s*"[~^]?(\d+\.\d+(?:\.\d+)?)"`, 0.85, "package.json"},
		},
		"ASP.NET": {
			{`X-AspNet-Version:\s*(\d+\.\d+(?:\.\d+)?)`, 0.95, "header"},
			{`ASP\.NET[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`X-AspNetMvc-Version:\s*(\d+\.\d+(?:\.\d+)?)`, 0.9, "MVC header"},
		},
		"ASP.NET Core": {
			{`\.NET\s*(\d+\.\d+(?:\.\d+)?)`, 0.8, "dotnet version"},
		},
		"Spring": {
			{`Spring[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
			{`spring-core.*?(\d+\.\d+(?:\.\d+)?)`, 0.8, "maven"},
		},
		"Spring Boot": {
			{`spring-boot.*?(\d+\.\d+(?:\.\d+)?)`, 0.9, "maven"},
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
		"Shopify": {
			{`Shopify\.theme.*?(\d+\.\d+(?:\.\d+)?)`, 0.7, "theme version"},
		},
		"Symfony": {
			{`Symfony[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
		},
		"FastAPI": {
			{`FastAPI[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
		},
		"Gin": {
			{`Gin[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`, 0.9, "explicit version"},
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

// ExtractVersionOptimized extracts version using pre-compiled patterns.
// This is exported for use by individual detector implementations.
func ExtractVersionOptimized(body string, framework string) VersionMatch {
	patterns, exists := frameworkVersionPatterns[framework]
	if !exists {
		return VersionMatch{Version: "unknown", Confidence: 0, Source: ""}
	}

	var bestMatch VersionMatch
	for _, p := range patterns {
		matches := p.re.FindStringSubmatch(body)
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

// isValidVersionString checks if a version string looks like a valid semver
func isValidVersionString(v string) bool {
	if len(v) == 0 || len(v) > 20 {
		return false
	}

	dotCount := 0
	for _, c := range v {
		if c == '.' {
			dotCount++
			if dotCount > 3 {
				return false
			}
		} else if !unicode.IsDigit(c) {
			return false
		}
	}
	return dotCount >= 1
}
