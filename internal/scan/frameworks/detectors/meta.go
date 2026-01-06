/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc, xyzeva,                                               :
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

	fw "github.com/dropalldatabases/sif/internal/scan/frameworks"
)

func init() {
	// Register all meta-framework detectors
	fw.Register(&nextjsDetector{})
	fw.Register(&nuxtDetector{})
	fw.Register(&sveltekitDetector{})
	fw.Register(&gatsbyDetector{})
	fw.Register(&remixDetector{})
	fw.Register(&astroDetector{})
}

// nextjsDetector detects Next.js framework.
type nextjsDetector struct{}

func (d *nextjsDetector) Name() string { return "Next.js" }

func (d *nextjsDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "__NEXT_DATA__", Weight: 0.5},
		{Pattern: "_next/static", Weight: 0.4},
		{Pattern: "__next", Weight: 0.3},
		{Pattern: "x-nextjs", Weight: 0.3, HeaderOnly: true},
	}
}

func (d *nextjsDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// nuxtDetector detects Nuxt.js framework.
type nuxtDetector struct{}

func (d *nuxtDetector) Name() string { return "Nuxt.js" }

func (d *nuxtDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "__NUXT__", Weight: 0.5},
		{Pattern: "_nuxt/", Weight: 0.4},
		{Pattern: "nuxt", Weight: 0.2},
	}
}

func (d *nuxtDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// sveltekitDetector detects SvelteKit framework.
type sveltekitDetector struct{}

func (d *sveltekitDetector) Name() string { return "SvelteKit" }

func (d *sveltekitDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "__sveltekit", Weight: 0.5},
		{Pattern: "_app/immutable", Weight: 0.4},
		{Pattern: "sveltekit", Weight: 0.3},
	}
}

func (d *sveltekitDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// gatsbyDetector detects Gatsby framework.
type gatsbyDetector struct{}

func (d *gatsbyDetector) Name() string { return "Gatsby" }

func (d *gatsbyDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "___gatsby", Weight: 0.5},
		{Pattern: "gatsby-", Weight: 0.4},
		{Pattern: "page-data.json", Weight: 0.3},
	}
}

func (d *gatsbyDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// remixDetector detects Remix framework.
type remixDetector struct{}

func (d *remixDetector) Name() string { return "Remix" }

func (d *remixDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "__remixContext", Weight: 0.5},
		{Pattern: "remix", Weight: 0.3},
		{Pattern: "_remix", Weight: 0.4},
	}
}

func (d *remixDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// astroDetector detects Astro framework.
type astroDetector struct{}

func (d *astroDetector) Name() string { return "Astro" }

func (d *astroDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `<meta name="generator" content="Astro`, Weight: 0.5},
		{Pattern: "astro-island", Weight: 0.5},
		{Pattern: "data-astro-cid-", Weight: 0.4},
		{Pattern: "/_astro/", Weight: 0.4},
		{Pattern: "data-astro-transition", Weight: 0.3},
		{Pattern: "data-astro-reload", Weight: 0.3},
		{Pattern: "data-astro-history", Weight: 0.3},
	}
}

func (d *astroDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}
