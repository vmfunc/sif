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
	// Register all meta-framework detectors
	fw.Register(&nextjsDetector{})
	fw.Register(&nuxtDetector{})
	fw.Register(&sveltekitDetector{})
	fw.Register(&gatsbyDetector{})
	fw.Register(&remixDetector{})
	fw.Register(&astroDetector{})
	fw.Register(&hugoDetector{})
	fw.Register(&jekyllDetector{})
	fw.Register(&docusaurusDetector{})
	fw.Register(&mkdocsDetector{})
	fw.Register(&eleventyDetector{})
	fw.Register(&hexoDetector{})
	fw.Register(&vuepressDetector{})
	fw.Register(&sphinxDetector{})
	fw.Register(&nikolaDetector{})
	fw.Register(&publiiDetector{})
}

type nextjsDetector struct{}

func (d *nextjsDetector) Name() string { return "Next.js" }

func (d *nextjsDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "__NEXT_DATA__", Weight: 0.5},
		// same attribute-form-vs-prose rationale as Angular's ng-version marker.
		{Pattern: `="/_next/static/`, Weight: 0.6},
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

type gatsbyDetector struct{}

func (d *gatsbyDetector) Name() string { return "Gatsby" }

func (d *gatsbyDetector) Signatures() []fw.Signature {
	// "gatsby-" alone cleared the detection threshold on prose merely naming a
	// plugin (a migration guide, a plugin comparison). the remaining patterns
	// are structural markers that only appear when gatsby rendered the page.
	return []fw.Signature{
		{Pattern: "___gatsby", Weight: 0.5},
		{Pattern: "/page-data/", Weight: 0.3},
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

type remixDetector struct{}

func (d *remixDetector) Name() string { return "Remix" }

func (d *remixDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "__remixContext", Weight: 0.5},
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

type astroDetector struct{}

func (d *astroDetector) Name() string { return "Astro" }

func (d *astroDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		// definitive quote-anchored marker; same threshold rationale as Next.js above.
		{Pattern: `<meta name="generator" content="Astro`, Weight: 1.1},
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

// The generator detectors below anchor on the content="<brand> value: real
// sites minify and reorder the meta, dropping the name="generator" prefix.

type hugoDetector struct{}

func (d *hugoDetector) Name() string { return "Hugo" }

func (d *hugoDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `content="Hugo 0.`, Weight: 0.6},
	}
}

func (d *hugoDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

type jekyllDetector struct{}

func (d *jekyllDetector) Name() string { return "Jekyll" }

func (d *jekyllDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `content="Jekyll v`, Weight: 0.6},
	}
}

func (d *jekyllDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

type docusaurusDetector struct{}

func (d *docusaurusDetector) Name() string { return "Docusaurus" }

func (d *docusaurusDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `content="Docusaurus v`, Weight: 0.6},
	}
}

func (d *docusaurusDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// mkdocsDetector detects MkDocs (including the Material theme).
type mkdocsDetector struct{}

func (d *mkdocsDetector) Name() string { return "MkDocs" }

func (d *mkdocsDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `content="mkdocs-`, Weight: 0.6},
	}
}

func (d *mkdocsDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// The generator detectors below anchor on the generator-attribute prefix
// (generator" content="<brand>) rather than a bare brand value.

// eleventyDetector detects the Eleventy (11ty) static site generator.
type eleventyDetector struct{}

func (d *eleventyDetector) Name() string { return "Eleventy" }

func (d *eleventyDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `generator" content="Eleventy`, Weight: 0.6},
	}
}

func (d *eleventyDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

type hexoDetector struct{}

func (d *hexoDetector) Name() string { return "Hexo" }

func (d *hexoDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `generator" content="Hexo`, Weight: 0.6},
	}
}

func (d *hexoDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

type vuepressDetector struct{}

func (d *vuepressDetector) Name() string { return "VuePress" }

func (d *vuepressDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `generator" content="VuePress`, Weight: 0.6},
	}
}

func (d *vuepressDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

type sphinxDetector struct{}

func (d *sphinxDetector) Name() string { return "Sphinx" }

func (d *sphinxDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "_static/documentation_options.js", Weight: 0.6},
		{Pattern: "sphinx-doc.org", Weight: 0.3},
		{Pattern: "_static/doctools.js", Weight: 0.3},
	}
}

func (d *sphinxDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

type nikolaDetector struct{}

func (d *nikolaDetector) Name() string { return "Nikola" }

func (d *nikolaDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `generator" content="Nikola`, Weight: 0.6},
	}
}

func (d *nikolaDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

type publiiDetector struct{}

func (d *publiiDetector) Name() string { return "Publii" }

func (d *publiiDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `generator" content="Publii`, Weight: 0.6},
	}
}

func (d *publiiDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}
