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
	// Register all CMS detectors
	fw.Register(&wordpressDetector{})
	fw.Register(&drupalDetector{})
	fw.Register(&joomlaDetector{})
	fw.Register(&magentoDetector{})
	fw.Register(&shopifyDetector{})
	fw.Register(&ghostDetector{})
}

// wordpressDetector detects WordPress CMS.
type wordpressDetector struct{}

func (d *wordpressDetector) Name() string { return "WordPress" }

func (d *wordpressDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "wp-content", Weight: 0.4},
		{Pattern: "wp-includes", Weight: 0.4},
		{Pattern: "wp-json", Weight: 0.3},
		{Pattern: "wordpress", Weight: 0.3},
		{Pattern: "wp-emoji", Weight: 0.2},
	}
}

func (d *wordpressDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// drupalDetector detects Drupal CMS.
type drupalDetector struct{}

func (d *drupalDetector) Name() string { return "Drupal" }

func (d *drupalDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "Drupal", Weight: 0.4, HeaderOnly: true},
		{Pattern: "drupal.js", Weight: 0.4},
		{Pattern: "/sites/default/files", Weight: 0.3},
		{Pattern: "Drupal.settings", Weight: 0.3},
	}
}

func (d *drupalDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// joomlaDetector detects Joomla CMS.
type joomlaDetector struct{}

func (d *joomlaDetector) Name() string { return "Joomla" }

func (d *joomlaDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "Joomla", Weight: 0.4},
		{Pattern: "/media/jui/", Weight: 0.4},
		{Pattern: "/components/com_", Weight: 0.3},
		{Pattern: "joomla.javascript", Weight: 0.3},
	}
}

func (d *joomlaDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// magentoDetector detects Magento CMS.
type magentoDetector struct{}

func (d *magentoDetector) Name() string { return "Magento" }

func (d *magentoDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "Magento", Weight: 0.4},
		{Pattern: "/static/frontend/", Weight: 0.4},
		{Pattern: "mage/", Weight: 0.3},
		{Pattern: "Mage.Cookies", Weight: 0.3},
	}
}

func (d *magentoDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// shopifyDetector detects Shopify platform.
type shopifyDetector struct{}

func (d *shopifyDetector) Name() string { return "Shopify" }

func (d *shopifyDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "Shopify", Weight: 0.5},
		{Pattern: "cdn.shopify.com", Weight: 0.4},
		{Pattern: "shopify-section", Weight: 0.4},
		{Pattern: "myshopify.com", Weight: 0.3},
	}
}

func (d *shopifyDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// ghostDetector detects Ghost CMS.
type ghostDetector struct{}

func (d *ghostDetector) Name() string { return "Ghost" }

func (d *ghostDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "ghost-", Weight: 0.4},
		{Pattern: "Ghost", Weight: 0.3, HeaderOnly: true},
		{Pattern: "/ghost/api/", Weight: 0.4},
	}
}

func (d *ghostDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}
