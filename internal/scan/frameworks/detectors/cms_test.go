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

func TestPlatformDetectors_Positive(t *testing.T) {
	tests := []struct {
		name     string
		detector fw.Detector
		body     string
		headers  http.Header
	}{
		{"TYPO3", &typo3Detector{}, `<meta name="generator" content="TYPO3 CMS">`, http.Header{}},
		{"TYPO3 4.x versioned", &typo3Detector{}, `<meta name="generator" content="TYPO3 4.5 CMS" />`, http.Header{}},
		{"Contao", &contaoDetector{}, `<meta name="generator" content="Contao Open Source CMS">`, http.Header{}},
		{"Wix header", &wixDetector{}, "", hdr("X-Wix-Request-Id", "1782416012.749990137421329")},
		{"Wix generator", &wixDetector{}, `<meta name="generator" content="Wix.com Website Builder">`, http.Header{}},
		{"Webflow reversed attrs", &webflowDetector{}, `<meta content="Webflow" name="generator"/>`, http.Header{}},
		{"Webflow html attrs", &webflowDetector{}, `<html data-wf-domain="x.com" data-wf-page="643064a18a585ec259a35532" data-wf-site="633ef3c0bd3be81b55ba5334" lang="en">`, http.Header{}},
		{"HubSpot", &hubspotDetector{}, `<meta name="generator" content="HubSpot">`, http.Header{}},
		{"PrestaShop global", &prestashopDetector{}, `<script>var prestashop = {"cart":{"products":[]}};</script>`, http.Header{}},
		{"Sitecore cookie", &sitecoreDetector{}, "", hdr("Set-Cookie", "SC_ANALYTICS_GLOBAL_COOKIE=8f2; path=/; HttpOnly")},
		{"OpenCart cookie", &opencartDetector{}, "", hdr("Set-Cookie", "OCSESSID=2a1c; path=/; HttpOnly")},
		{"DotNetNuke cookie", &dnnDetector{}, "", hdr("Set-Cookie", "DNNPersonalization=; expires=Mon; path=/")},
		{"DotNetNuke mobile cookie", &dnnDetector{}, "", hdr("Set-Cookie", "dnn_IsMobile=False; path=/; HttpOnly")},
		{"Liferay header", &liferayDetector{}, "", hdr("X-Liferay-Request-Guest-User", "true")},
		{"Liferay body behind CDN", &liferayDetector{}, `<script>Liferay.ThemeDisplay = {getUserId:function(){return 0;}};</script>`, http.Header{}},
		{"Squarespace context", &squarespaceDetector{}, `<script>Static.SQUARESPACE_CONTEXT = {"website":{"id":"x"}};</script>`, http.Header{}},
		{"WooCommerce store", &woocommerceDetector{}, `<link rel="stylesheet" href="/wp-content/plugins/woocommerce/assets/css/woocommerce.css"><body class="woocommerce-page">`, http.Header{}},
		{"Shopify storefront header", &shopifyDetector{}, "", hdr("X-Shopify-Stage", "production")},
		{"Craft header", &craftDetector{}, "", hdr("X-Powered-By", "Craft CMS,SEOmatic")},
		{"Craft csrf cookie", &craftDetector{}, "", hdr("Set-Cookie", "CRAFT_CSRF_TOKEN=a1b2c3; path=/; HttpOnly")},
		{"Concrete CMS 9", &concreteDetector{}, `<meta name="generator" content="Concrete CMS"/>`, http.Header{}},
		{"concrete5 legacy", &concreteDetector{}, `<meta name="generator" content="concrete5.7.5.13">`, http.Header{}},
		{"Bitrix assets", &bitrixDetector{}, `<script src="/bitrix/js/main/core/core.js"></script>`, http.Header{}},
		{"Blogger generator", &bloggerDetector{}, `<meta content='blogger' name='generator'/>`, http.Header{}},
		{"MediaWiki generator", &mediawikiDetector{}, `<meta name="generator" content="MediaWiki 1.47.0"/>`, http.Header{}},
		{"Discourse generator", &discourseDetector{}, `<meta name="generator" content="Discourse 3.2.0 - https://github.com/discourse/discourse">`, http.Header{}},
		{"XenForo attrs", &xenforoDetector{}, `<html data-app="public" data-xf-init><script src="/js/xf/core.min.js"></script>`, http.Header{}},
		{"Moodle cookie", &moodleDetector{}, "", hdr("Set-Cookie", "MoodleSession=2a1c; path=/; HttpOnly")},
		{"Plone generator", &ploneDetector{}, `<meta name="generator" content="Plone 6 - https://plone.org"/>`, http.Header{}},
		{"Grav generator", &gravDetector{}, `<meta name="generator" content="GravCMS" />`, http.Header{}},
		{"Textpattern generator", &textpatternDetector{}, `<meta name="generator" content="Textpattern CMS">`, http.Header{}},
		{"October cookie", &octoberDetector{}, "", hdr("Set-Cookie", "october_session=eyJpdiI6Ijk; path=/; httponly")},
		{"Statamic session cookie", &statamicDetector{}, "", hdr("Set-Cookie", "statamic_session=eyJpdiI6Ijd; path=/; secure; httponly")},
		{"Statamic branded cookie", &statamicDetector{}, "", hdr("Set-Cookie", "delicious_statamic_cookies=eyJpdiI6Ijh; path=/; secure")},
		{"Flarum bootstrap", &flarumDetector{}, `<div id="app"></div><script id="flarum-json-payload-x"></script><script src="/assets/forum-en.js"></script>`, http.Header{}},
		{"NodeBB assets", &nodebbDetector{}, `<script src="/assets/nodebb.min.js"></script>`, http.Header{}},
		{"XWiki attrs", &xwikiDetector{}, `<html data-xwiki-document="Main.WebHome"><a href="/xwiki/bin/view/Main/">home</a>`, http.Header{}},
		{"Bolt generator", &boltDetector{}, `<meta name="generator" content="Bolt">`, http.Header{}},
		{"ExpressionEngine csrf field", &expressionengineDetector{}, `<input type="hidden" name="csrf_token" value="x"><script>EE.exp_csrf_token="ab12";</script>`, http.Header{}},
		{"ExpressionEngine cookie", &expressionengineDetector{}, "", hdr("Set-Cookie", "exp_last_visit=1782; path=/; httponly")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, _ := tt.detector.Detect(tt.body, tt.headers)
			if conf <= 0.5 {
				t.Errorf("%s: confidence = %.3f, want > 0.5", tt.name, conf)
			}
		})
	}
}

func TestPlatformDetectors_Negative(t *testing.T) {
	tests := []struct {
		name     string
		detector fw.Detector
		body     string
		headers  http.Header
	}{
		{"Contao description", &contaoDetector{}, `<meta name="description" content="Contao is a powerful open source CMS">`, http.Header{}},
		{"PrestaShop keywords", &prestashopDetector{}, `<meta name="keywords" content="prestashop addons, prestashop themes">`, http.Header{}},
		{"TYPO3 prose", &typo3Detector{}, `<p>TYPO3 CMS is a popular enterprise CMS.</p>`, http.Header{}},
		{"Webflow review", &webflowDetector{}, `<meta property="og:title" content="Webflow Review 2026">`, http.Header{}},
		{"HubSpot pricing", &hubspotDetector{}, `<meta property="og:title" content="HubSpot Pricing 2026">`, http.Header{}},
		{"Webflow brand og", &webflowDetector{}, `<meta property="og:site_name" content="Webflow">`, http.Header{}},
		{"HubSpot brand og", &hubspotDetector{}, `<meta property="og:title" content="HubSpot">`, http.Header{}},
		{"Wix mention", &wixDetector{}, `<p>I built my first site on Wix.com years ago.</p>`, http.Header{}},
		{"Sitecore plain cookie", &sitecoreDetector{}, "", hdr("Set-Cookie", "sessionid=abc; path=/")},
		{"OpenCart plain cookie", &opencartDetector{}, "", hdr("Set-Cookie", "PHPSESSID=abc; path=/")},
		{"DotNetNuke plain cookie", &dnnDetector{}, "", hdr("Set-Cookie", "ASP.NET_SessionId=abc; path=/")},
		{"Liferay plain header", &liferayDetector{}, "", hdr("Server", "nginx/1.25.3")},
		{"Liferay prose", &liferayDetector{}, "<p>Liferay is a Java portal platform.</p>", http.Header{}},
		{"Squarespace prose", &squarespaceDetector{}, `<p>Squarespace is a hosted website builder.</p>`, http.Header{}},
		{"Shopify cdn link header", &shopifyDetector{}, "", hdr("Link", "<https://cdn.shopify.com/s/x.js>; rel=preload")},
		{"Shopify cdn body only", &shopifyDetector{}, `<script src="https://cdn.shopify.com/s/buy-button.js"></script>`, http.Header{}},
		{"WooCommerce plain WP", &woocommerceDetector{}, `<link href="/wp-content/themes/storefront/style.css"><body class="home page">`, http.Header{}},
		{"WooCommerce class only", &woocommerceDetector{}, `<body class="woocommerce-page">`, http.Header{}},
		{"Craft unrelated header", &craftDetector{}, "", hdr("Server", "nginx/1.25.3")},
		{"Concrete brand og", &concreteDetector{}, `<meta property="og:title" content="Concrete CMS">`, http.Header{}},
		{"Bitrix prose", &bitrixDetector{}, `<p>We migrated from Bitrix to Shopify last year.</p>`, http.Header{}},
		{"Blogger comparison prose", &bloggerDetector{}, `<meta property="og:title" content="Blogger vs WordPress">`, http.Header{}},
		{"MediaWiki brand og", &mediawikiDetector{}, `<meta property="og:title" content="MediaWiki">`, http.Header{}},
		{"Discourse comparison og", &discourseDetector{}, `<meta property="og:title" content="Discourse vs Reddit">`, http.Header{}},
		{"XenForo prose", &xenforoDetector{}, `<p>XenForo is a commercial forum platform.</p>`, http.Header{}},
		{"Moodle unrelated cookie", &moodleDetector{}, "", hdr("Set-Cookie", "sessionid=abc; path=/")},
		{"Moodle minified collision", &moodleDetector{}, `<script>var M={};M.cfg=window.location;M.init();</script>`, http.Header{}},
		{"Plone brand og", &ploneDetector{}, `<meta property="og:title" content="Plone">`, http.Header{}},
		{"Grav prose", &gravDetector{}, `<meta property="og:title" content="Grav"><p>Grav is a flat-file CMS.</p>`, http.Header{}},
		{"Textpattern brand og", &textpatternDetector{}, `<meta property="og:title" content="Textpattern">`, http.Header{}},
		{"Statamic unrelated header", &statamicDetector{}, "", hdr("Server", "nginx/1.25.3")},
		{"Statamic domain in link header", &statamicDetector{}, "", hdr("Link", "<https://cdn.statamic.com/a.js>; rel=preload")},
		{"Flarum prose", &flarumDetector{}, `<p>Flarum is a delightfully simple forum platform.</p>`, http.Header{}},
		{"Flarum near miss id", &flarumDetector{}, `<div id="flarumish-widget"></div>`, http.Header{}},
		{"Flarum generic forum asset", &flarumDetector{}, `<img src="/assets/forum-banner.png"><link href="/assets/forum-theme.css">`, http.Header{}},
		{"XWiki prose", &xwikiDetector{}, `<p>XWiki is an enterprise wiki platform.</p>`, http.Header{}},
		{"Bolt brand og", &boltDetector{}, `<meta property="og:title" content="Bolt">`, http.Header{}},
		{"ExpressionEngine prose", &expressionengineDetector{}, `<p>ExpressionEngine is a flexible PHP CMS.</p>`, http.Header{}},
		{"ExpressionEngine exp prefix collision", &expressionengineDetector{}, "", hdr("Set-Cookie", "exp_date=2026; path=/")},
		{"NodeBB prose", &nodebbDetector{}, `<p>We run NodeBB for our community forum.</p>`, http.Header{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf, _ := tt.detector.Detect(tt.body, tt.headers)
			if conf > 0.5 {
				t.Errorf("%s: confidence = %.3f, want <= 0.5", tt.name, conf)
			}
		})
	}
}

func TestPlatformDetectors_Version(t *testing.T) {
	tests := []struct {
		name     string
		detector fw.Detector
		body     string
		want     string
	}{
		{"TYPO3 4.x", &typo3Detector{}, `<meta name="generator" content="TYPO3 4.5 CMS" />`, "4.5"},
		{"TYPO3 modern", &typo3Detector{}, `<meta name="generator" content="TYPO3 CMS">`, "unknown"},
		{"MediaWiki", &mediawikiDetector{}, `<meta name="generator" content="MediaWiki 1.47.0"/>`, "1.47.0"},
		{"Discourse", &discourseDetector{}, `<meta name="generator" content="Discourse 3.2.0 - https://github.com/discourse/discourse">`, "3.2.0"},
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
