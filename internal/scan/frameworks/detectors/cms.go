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
	// Register all CMS detectors
	fw.Register(&wordpressDetector{})
	fw.Register(&drupalDetector{})
	fw.Register(&joomlaDetector{})
	fw.Register(&magentoDetector{})
	fw.Register(&shopifyDetector{})
	fw.Register(&ghostDetector{})
	fw.Register(&bitrixDetector{})
	fw.Register(&bloggerDetector{})
	fw.Register(&boltDetector{})
	fw.Register(&concreteDetector{})
	fw.Register(&contaoDetector{})
	fw.Register(&craftDetector{})
	fw.Register(&discourseDetector{})
	fw.Register(&dnnDetector{})
	fw.Register(&expressionengineDetector{})
	fw.Register(&flarumDetector{})
	fw.Register(&gravDetector{})
	fw.Register(&hubspotDetector{})
	fw.Register(&liferayDetector{})
	fw.Register(&mediawikiDetector{})
	fw.Register(&moodleDetector{})
	fw.Register(&nodebbDetector{})
	fw.Register(&octoberDetector{})
	fw.Register(&opencartDetector{})
	fw.Register(&ploneDetector{})
	fw.Register(&prestashopDetector{})
	fw.Register(&sitecoreDetector{})
	fw.Register(&squarespaceDetector{})
	fw.Register(&statamicDetector{})
	fw.Register(&textpatternDetector{})
	fw.Register(&typo3Detector{})
	fw.Register(&webflowDetector{})
	fw.Register(&wixDetector{})
	fw.Register(&woocommerceDetector{})
	fw.Register(&xenforoDetector{})
	fw.Register(&xwikiDetector{})
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
		{Pattern: "x-shopify", Weight: 0.5, HeaderOnly: true},
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
		{Pattern: `<meta name="generator" content="Ghost`, Weight: 0.4},
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

// typo3Detector detects the TYPO3 CMS.
type typo3Detector struct{}

func (d *typo3Detector) Name() string { return "TYPO3" }

func (d *typo3Detector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `generator" content="TYPO3`, Weight: 0.6},
	}
}

func (d *typo3Detector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// contaoDetector detects the Contao CMS.
type contaoDetector struct{}

func (d *contaoDetector) Name() string { return "Contao" }

func (d *contaoDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `content="Contao Open Source CMS"`, Weight: 0.6},
	}
}

func (d *contaoDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// wixDetector detects sites built on the Wix website builder.
type wixDetector struct{}

func (d *wixDetector) Name() string { return "Wix" }

func (d *wixDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "X-Wix-Request-Id", Weight: 0.5, HeaderOnly: true},
		{Pattern: `content="Wix.com Website Builder"`, Weight: 0.5},
	}
}

func (d *wixDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// webflowDetector detects sites built on Webflow.
type webflowDetector struct{}

func (d *webflowDetector) Name() string { return "Webflow" }

func (d *webflowDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "data-wf-page", Weight: 0.6},
		{Pattern: `content="Webflow" name="generator"`, Weight: 0.6},
	}
}

func (d *webflowDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// hubspotDetector detects pages built on the HubSpot CMS.
type hubspotDetector struct{}

func (d *hubspotDetector) Name() string { return "HubSpot" }

func (d *hubspotDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `generator" content="HubSpot"`, Weight: 0.6},
	}
}

func (d *hubspotDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// prestashopDetector detects the PrestaShop e-commerce platform.
type prestashopDetector struct{}

func (d *prestashopDetector) Name() string { return "PrestaShop" }

func (d *prestashopDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "var prestashop = {", Weight: 0.6},
	}
}

func (d *prestashopDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// sitecoreDetector detects the Sitecore platform.
type sitecoreDetector struct{}

func (d *sitecoreDetector) Name() string { return "Sitecore" }

func (d *sitecoreDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "SC_ANALYTICS_GLOBAL_COOKIE", Weight: 0.6, HeaderOnly: true},
	}
}

func (d *sitecoreDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// opencartDetector detects the OpenCart e-commerce platform.
type opencartDetector struct{}

func (d *opencartDetector) Name() string { return "OpenCart" }

func (d *opencartDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "OCSESSID", Weight: 0.6, HeaderOnly: true},
	}
}

func (d *opencartDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// dnnDetector detects the DNN (DotNetNuke) platform.
type dnnDetector struct{}

func (d *dnnDetector) Name() string { return "DotNetNuke" }

func (d *dnnDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "DNNPersonalization", Weight: 0.6, HeaderOnly: true},
		{Pattern: "dnn_IsMobile", Weight: 0.6, HeaderOnly: true},
	}
}

func (d *dnnDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// liferayDetector detects the Liferay portal.
type liferayDetector struct{}

func (d *liferayDetector) Name() string { return "Liferay" }

func (d *liferayDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "X-Liferay", Weight: 0.6, HeaderOnly: true},
		{Pattern: "Liferay.ThemeDisplay", Weight: 0.5},
	}
}

func (d *liferayDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// squarespaceDetector detects sites built on Squarespace.
type squarespaceDetector struct{}

func (d *squarespaceDetector) Name() string { return "Squarespace" }

func (d *squarespaceDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "SQUARESPACE_CONTEXT", Weight: 0.6},
	}
}

func (d *squarespaceDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// woocommerceDetector detects the WooCommerce WordPress plugin.
type woocommerceDetector struct{}

func (d *woocommerceDetector) Name() string { return "WooCommerce" }

func (d *woocommerceDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "/plugins/woocommerce/", Weight: 0.6},
		{Pattern: "woocommerce_params", Weight: 0.5},
		{Pattern: "wc-ajax", Weight: 0.4},
		{Pattern: "woocommerce-page", Weight: 0.4},
	}
}

func (d *woocommerceDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// craftDetector detects Craft CMS.
type craftDetector struct{}

func (d *craftDetector) Name() string { return "Craft CMS" }

func (d *craftDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "Craft CMS", Weight: 0.6, HeaderOnly: true},
		{Pattern: "CRAFT_CSRF_TOKEN", Weight: 0.5, HeaderOnly: true},
		{Pattern: "CraftSessionId", Weight: 0.4, HeaderOnly: true},
	}
}

func (d *craftDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// concreteDetector detects Concrete CMS (formerly concrete5).
type concreteDetector struct{}

func (d *concreteDetector) Name() string { return "Concrete CMS" }

func (d *concreteDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `generator" content="Concrete CMS"`, Weight: 0.6},
		{Pattern: `generator" content="concrete5`, Weight: 0.6},
	}
}

func (d *concreteDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// bitrixDetector detects the 1C-Bitrix platform.
type bitrixDetector struct{}

func (d *bitrixDetector) Name() string { return "Bitrix" }

func (d *bitrixDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "/bitrix/js/", Weight: 0.6},
		{Pattern: "/bitrix/templates/", Weight: 0.5},
		{Pattern: "BITRIX_SM_", Weight: 0.4},
		{Pattern: "/bitrix/cache/", Weight: 0.3},
	}
}

func (d *bitrixDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// bloggerDetector detects Google's Blogger platform.
type bloggerDetector struct{}

func (d *bloggerDetector) Name() string { return "Blogger" }

func (d *bloggerDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "content='blogger' name='generator'", Weight: 0.6},
	}
}

func (d *bloggerDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// mediawikiDetector detects MediaWiki.
type mediawikiDetector struct{}

func (d *mediawikiDetector) Name() string { return "MediaWiki" }

func (d *mediawikiDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `generator" content="MediaWiki`, Weight: 0.6},
	}
}

func (d *mediawikiDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// discourseDetector detects the Discourse forum platform.
type discourseDetector struct{}

func (d *discourseDetector) Name() string { return "Discourse" }

func (d *discourseDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `generator" content="Discourse`, Weight: 0.6},
	}
}

func (d *discourseDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// xenforoDetector detects the XenForo forum platform.
type xenforoDetector struct{}

func (d *xenforoDetector) Name() string { return "XenForo" }

func (d *xenforoDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "data-xf-init", Weight: 0.5},
		{Pattern: "/js/xf/", Weight: 0.4},
		{Pattern: "data-xf-key", Weight: 0.3},
	}
}

func (d *xenforoDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// moodleDetector detects the Moodle learning platform.
type moodleDetector struct{}

func (d *moodleDetector) Name() string { return "Moodle" }

func (d *moodleDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "MoodleSession", Weight: 0.6, HeaderOnly: true},
	}
}

func (d *moodleDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// ploneDetector detects the Plone CMS.
type ploneDetector struct{}

func (d *ploneDetector) Name() string { return "Plone" }

func (d *ploneDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `generator" content="Plone`, Weight: 0.6},
	}
}

func (d *ploneDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// gravDetector detects the Grav flat-file CMS.
type gravDetector struct{}

func (d *gravDetector) Name() string { return "Grav" }

func (d *gravDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `content="GravCMS"`, Weight: 0.6},
	}
}

func (d *gravDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// textpatternDetector detects the Textpattern CMS.
type textpatternDetector struct{}

func (d *textpatternDetector) Name() string { return "Textpattern" }

func (d *textpatternDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `generator" content="Textpattern`, Weight: 0.6},
	}
}

func (d *textpatternDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// octoberDetector detects the October CMS (Laravel-based).
type octoberDetector struct{}

func (d *octoberDetector) Name() string { return "October CMS" }

func (d *octoberDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "october_session", Weight: 0.6, HeaderOnly: true},
	}
}

func (d *octoberDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// statamicDetector detects the Statamic CMS (Laravel-based).
type statamicDetector struct{}

func (d *statamicDetector) Name() string { return "Statamic" }

func (d *statamicDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "statamic_", Weight: 0.6, HeaderOnly: true},
	}
}

func (d *statamicDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// flarumDetector detects the Flarum forum platform.
type flarumDetector struct{}

func (d *flarumDetector) Name() string { return "Flarum" }

func (d *flarumDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `id="flarum-`, Weight: 0.6},
	}
}

func (d *flarumDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// nodebbDetector detects the NodeBB forum platform.
type nodebbDetector struct{}

func (d *nodebbDetector) Name() string { return "NodeBB" }

func (d *nodebbDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "assets/nodebb", Weight: 0.6},
	}
}

func (d *nodebbDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// xwikiDetector detects the XWiki platform.
type xwikiDetector struct{}

func (d *xwikiDetector) Name() string { return "XWiki" }

func (d *xwikiDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "data-xwiki-", Weight: 0.5},
		{Pattern: "/xwiki/bin/", Weight: 0.4},
	}
}

func (d *xwikiDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// boltDetector detects the Bolt CMS (Symfony-based).
type boltDetector struct{}

func (d *boltDetector) Name() string { return "Bolt CMS" }

func (d *boltDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: `generator" content="Bolt"`, Weight: 0.6},
	}
}

func (d *boltDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}

// expressionengineDetector detects ExpressionEngine.
type expressionengineDetector struct{}

func (d *expressionengineDetector) Name() string { return "ExpressionEngine" }

func (d *expressionengineDetector) Signatures() []fw.Signature {
	return []fw.Signature{
		{Pattern: "exp_csrf", Weight: 0.5},
		{Pattern: "exp_sessionid", Weight: 0.4, HeaderOnly: true},
		{Pattern: "exp_last_visit", Weight: 0.4, HeaderOnly: true},
	}
}

func (d *expressionengineDetector) Detect(body string, headers http.Header) (float32, string) {
	base := fw.NewBaseDetector(d.Name(), d.Signatures())
	score := base.MatchSignatures(body, headers)
	confidence := sigmoidConfidence(score)

	var version string
	if confidence > 0.5 {
		version = fw.ExtractVersionOptimized(body, d.Name()).Version
	}
	return confidence, version
}
