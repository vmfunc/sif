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

package frameworks

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/dropalldatabases/sif/pkg/logger"
)

type FrameworkResult struct {
	Name              string   `json:"name"`
	Version           string   `json:"version"`
	Confidence        float32  `json:"confidence"`
	VersionConfidence float32  `json:"version_confidence"`
	CVEs              []string `json:"cves,omitempty"`
	Suggestions       []string `json:"suggestions,omitempty"`
	RiskLevel         string   `json:"risk_level,omitempty"`
}

type FrameworkSignature struct {
	Pattern    string
	Weight     float32
	HeaderOnly bool
}

var frameworkSignatures = map[string][]FrameworkSignature{
	"Laravel": {
		{Pattern: `laravel_session`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `XSRF-TOKEN`, Weight: 0.3, HeaderOnly: true},
		{Pattern: `<meta name="csrf-token"`, Weight: 0.3},
	},
	"Django": {
		{Pattern: `csrfmiddlewaretoken`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `csrftoken`, Weight: 0.3, HeaderOnly: true},
		{Pattern: `django.contrib`, Weight: 0.3},
		{Pattern: `django.core`, Weight: 0.3},
		{Pattern: `__admin_media_prefix__`, Weight: 0.3},
	},
	"Ruby on Rails": {
		{Pattern: `csrf-param`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `csrf-token`, Weight: 0.3, HeaderOnly: true},
		{Pattern: `_rails_session`, Weight: 0.3, HeaderOnly: true},
		{Pattern: `ruby-on-rails`, Weight: 0.3},
		{Pattern: `rails-env`, Weight: 0.3},
		{Pattern: `data-turbo`, Weight: 0.2},
	},
	"Express.js": {
		{Pattern: `Express`, Weight: 0.5, HeaderOnly: true},
		{Pattern: `connect.sid`, Weight: 0.3, HeaderOnly: true},
	},
	"ASP.NET": {
		{Pattern: `X-AspNet-Version`, Weight: 0.5, HeaderOnly: true},
		{Pattern: `X-AspNetMvc-Version`, Weight: 0.5, HeaderOnly: true},
		{Pattern: `ASP.NET`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `__VIEWSTATE`, Weight: 0.4},
		{Pattern: `__EVENTVALIDATION`, Weight: 0.3},
		{Pattern: `__VIEWSTATEGENERATOR`, Weight: 0.3},
		{Pattern: `.aspx`, Weight: 0.2},
		{Pattern: `.ashx`, Weight: 0.2},
		{Pattern: `.asmx`, Weight: 0.2},
		{Pattern: `asp.net_sessionid`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `X-Powered-By: ASP.NET`, Weight: 0.4, HeaderOnly: true},
	},
	"ASP.NET Core": {
		{Pattern: `.AspNetCore.`, Weight: 0.5, HeaderOnly: true},
		{Pattern: `blazor`, Weight: 0.4},
		{Pattern: `_blazor`, Weight: 0.4},
		{Pattern: `dotnet`, Weight: 0.2, HeaderOnly: true},
	},
	"Spring": {
		{Pattern: `org.springframework`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `spring-security`, Weight: 0.3, HeaderOnly: true},
		{Pattern: `JSESSIONID`, Weight: 0.3, HeaderOnly: true},
		{Pattern: `X-Application-Context`, Weight: 0.3, HeaderOnly: true},
	},
	"Spring Boot": {
		{Pattern: `spring-boot`, Weight: 0.5},
		{Pattern: `actuator`, Weight: 0.3},
		{Pattern: `whitelabel`, Weight: 0.2},
	},
	"Flask": {
		{Pattern: `Werkzeug`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `flask`, Weight: 0.3, HeaderOnly: true},
		{Pattern: `jinja2`, Weight: 0.3},
	},
	"Next.js": {
		{Pattern: `__NEXT_DATA__`, Weight: 0.5},
		{Pattern: `_next/static`, Weight: 0.4},
		{Pattern: `__next`, Weight: 0.3},
		{Pattern: `x-nextjs`, Weight: 0.3, HeaderOnly: true},
	},
	"Nuxt.js": {
		{Pattern: `__NUXT__`, Weight: 0.5},
		{Pattern: `_nuxt/`, Weight: 0.4},
		{Pattern: `nuxt`, Weight: 0.2},
	},
	"Vue.js": {
		{Pattern: `data-v-`, Weight: 0.5},
		{Pattern: `Vue.js`, Weight: 0.4},
		{Pattern: `vue.runtime`, Weight: 0.4},
		{Pattern: `vue.min.js`, Weight: 0.4},
		{Pattern: `__vue__`, Weight: 0.3},
		{Pattern: `v-cloak`, Weight: 0.3},
	},
	"Angular": {
		{Pattern: `ng-version`, Weight: 0.5},
		{Pattern: `ng-app`, Weight: 0.4},
		{Pattern: `ng-controller`, Weight: 0.4},
		{Pattern: `angular.js`, Weight: 0.4},
		{Pattern: `angular.min.js`, Weight: 0.4},
		{Pattern: `ng-binding`, Weight: 0.3},
		{Pattern: `_nghost`, Weight: 0.3},
		{Pattern: `_ngcontent`, Weight: 0.3},
	},
	"React": {
		{Pattern: `data-reactroot`, Weight: 0.5},
		{Pattern: `react-dom`, Weight: 0.4},
		{Pattern: `__REACT_DEVTOOLS`, Weight: 0.4},
		{Pattern: `react.production`, Weight: 0.4},
		{Pattern: `_reactRootContainer`, Weight: 0.3},
	},
	"Svelte": {
		{Pattern: `svelte`, Weight: 0.4},
		{Pattern: `__svelte`, Weight: 0.5},
		{Pattern: `svelte-`, Weight: 0.3},
	},
	"SvelteKit": {
		{Pattern: `__sveltekit`, Weight: 0.5},
		{Pattern: `_app/immutable`, Weight: 0.4},
		{Pattern: `sveltekit`, Weight: 0.3},
	},
	"Remix": {
		{Pattern: `__remixContext`, Weight: 0.5},
		{Pattern: `remix`, Weight: 0.3},
		{Pattern: `_remix`, Weight: 0.4},
	},
	"Gatsby": {
		{Pattern: `___gatsby`, Weight: 0.5},
		{Pattern: `gatsby-`, Weight: 0.4},
		{Pattern: `page-data.json`, Weight: 0.3},
	},
	"WordPress": {
		{Pattern: `wp-content`, Weight: 0.4},
		{Pattern: `wp-includes`, Weight: 0.4},
		{Pattern: `wp-json`, Weight: 0.3},
		{Pattern: `wordpress`, Weight: 0.3},
		{Pattern: `wp-emoji`, Weight: 0.2},
	},
	"Drupal": {
		{Pattern: `Drupal`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `drupal.js`, Weight: 0.4},
		{Pattern: `/sites/default/files`, Weight: 0.3},
		{Pattern: `Drupal.settings`, Weight: 0.3},
	},
	"Joomla": {
		{Pattern: `Joomla`, Weight: 0.4},
		{Pattern: `/media/jui/`, Weight: 0.4},
		{Pattern: `/components/com_`, Weight: 0.3},
		{Pattern: `joomla.javascript`, Weight: 0.3},
	},
	"Magento": {
		{Pattern: `Magento`, Weight: 0.4},
		{Pattern: `/static/frontend/`, Weight: 0.4},
		{Pattern: `mage/`, Weight: 0.3},
		{Pattern: `Mage.Cookies`, Weight: 0.3},
	},
	"Shopify": {
		{Pattern: `Shopify`, Weight: 0.5},
		{Pattern: `cdn.shopify.com`, Weight: 0.4},
		{Pattern: `shopify-section`, Weight: 0.4},
		{Pattern: `myshopify.com`, Weight: 0.3},
	},
	"Ghost": {
		{Pattern: `ghost-`, Weight: 0.4},
		{Pattern: `Ghost`, Weight: 0.3, HeaderOnly: true},
		{Pattern: `/ghost/api/`, Weight: 0.4},
	},
	"Symfony": {
		{Pattern: `symfony`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `sf_`, Weight: 0.3, HeaderOnly: true},
		{Pattern: `_sf2_`, Weight: 0.3, HeaderOnly: true},
	},
	"FastAPI": {
		{Pattern: `fastapi`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `starlette`, Weight: 0.3, HeaderOnly: true},
	},
	"Gin": {
		{Pattern: `gin-gonic`, Weight: 0.4},
		{Pattern: `gin`, Weight: 0.2, HeaderOnly: true},
	},
	"Phoenix": {
		{Pattern: `_csrf_token`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `phx-`, Weight: 0.3},
		{Pattern: `phoenix`, Weight: 0.2},
	},
	"Ember.js": {
		{Pattern: `ember`, Weight: 0.4},
		{Pattern: `ember-cli`, Weight: 0.4},
		{Pattern: `data-ember`, Weight: 0.3},
	},
	"Backbone.js": {
		{Pattern: `backbone`, Weight: 0.4},
		{Pattern: `Backbone.`, Weight: 0.4},
	},
	"Meteor": {
		{Pattern: `__meteor_runtime_config__`, Weight: 0.5},
		{Pattern: `meteor`, Weight: 0.3},
	},
	"Strapi": {
		{Pattern: `strapi`, Weight: 0.4},
		{Pattern: `/api/`, Weight: 0.2},
	},
	"AdonisJS": {
		{Pattern: `adonis`, Weight: 0.4},
		{Pattern: `_csrf`, Weight: 0.2, HeaderOnly: true},
	},
	"CakePHP": {
		{Pattern: `cakephp`, Weight: 0.4},
		{Pattern: `cake`, Weight: 0.2},
	},
	"CodeIgniter": {
		{Pattern: `codeigniter`, Weight: 0.4},
		{Pattern: `ci_session`, Weight: 0.4, HeaderOnly: true},
	},
}

// frameworkMatch holds the result of checking a single framework
type frameworkMatch struct {
	framework  string
	confidence float32
}

func DetectFramework(url string, timeout time.Duration, logdir string) (*FrameworkResult, error) {
	fmt.Println(styles.Separator.Render("🔍 Starting " + styles.Status.Render("Framework Detection") + "..."))

	frameworklog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Framework Detection 🔍",
	}).With("url", url)

	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Limit body read to 5MB to prevent memory exhaustion
	const maxBodySize = 5 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, err
	}
	bodyStr := string(body)

	// concurrent framework detection
	results := make(chan frameworkMatch, len(frameworkSignatures))
	var wg sync.WaitGroup

	for framework, signatures := range frameworkSignatures {
		wg.Add(1)
		go func(fw string, sigs []FrameworkSignature) {
			defer wg.Done()

			var weightedScore float32
			var totalWeight float32

			for _, sig := range sigs {
				totalWeight += sig.Weight

				if sig.HeaderOnly {
					if containsHeader(resp.Header, sig.Pattern) {
						weightedScore += sig.Weight
					}
				} else if strings.Contains(bodyStr, sig.Pattern) {
					weightedScore += sig.Weight
				}
			}

			confidence := float32(1.0 / (1.0 + math.Exp(-float64(weightedScore/totalWeight)*6.0)))
			results <- frameworkMatch{framework: fw, confidence: confidence}
		}(framework, signatures)
	}

	// close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// find the best match
	var bestMatch string
	var highestConfidence float32

	for match := range results {
		if match.confidence > highestConfidence {
			highestConfidence = match.confidence
			bestMatch = match.framework
		}
	}

	if highestConfidence > 0.5 { // threshold for detection
		versionMatch := extractVersionOptimized(bodyStr, bestMatch)
		cves, suggestions := getVulnerabilities(bestMatch, versionMatch.Version)

		result := &FrameworkResult{
			Name:              bestMatch,
			Version:           versionMatch.Version,
			Confidence:        highestConfidence,
			VersionConfidence: versionMatch.Confidence,
			CVEs:              cves,
			Suggestions:       suggestions,
			RiskLevel:         getRiskLevel(cves),
		}

		if logdir != "" {
			logEntry := fmt.Sprintf("Detected framework: %s (version: %s, confidence: %.2f, version_confidence: %.2f)\n",
				bestMatch, versionMatch.Version, highestConfidence, versionMatch.Confidence)
			if len(cves) > 0 {
				logEntry += fmt.Sprintf("  Risk Level: %s\n", result.RiskLevel)
				logEntry += fmt.Sprintf("  CVEs: %v\n", cves)
				logEntry += fmt.Sprintf("  Recommendations: %v\n", suggestions)
			}
			logger.Write(url, logdir, logEntry)
		}

		frameworklog.Infof("Detected %s framework (version: %s, confidence: %.2f)",
			styles.Highlight.Render(bestMatch), versionMatch.Version, highestConfidence)

		if versionMatch.Confidence > 0 {
			frameworklog.Debugf("Version detected from: %s (confidence: %.2f)",
				versionMatch.Source, versionMatch.Confidence)
		}

		if len(cves) > 0 {
			frameworklog.Warnf("Risk level: %s", styles.SeverityHigh.Render(result.RiskLevel))
			for _, cve := range cves {
				frameworklog.Warnf("Found potential vulnerability: %s", styles.Highlight.Render(cve))
			}
			for _, suggestion := range suggestions {
				frameworklog.Infof("Recommendation: %s", suggestion)
			}
		}

		return result, nil
	}

	frameworklog.Info("No framework detected with sufficient confidence")
	return nil, nil
}

func containsHeader(headers http.Header, signature string) bool {
	sigLower := strings.ToLower(signature)

	// check header names
	for name := range headers {
		if strings.Contains(strings.ToLower(name), sigLower) {
			return true
		}
	}

	// check header values
	for _, values := range headers {
		for _, value := range values {
			if strings.Contains(strings.ToLower(value), sigLower) {
				return true
			}
		}
	}
	return false
}

func detectVersion(body string, framework string) string {
	match := extractVersionOptimized(body, framework)
	return match.Version
}

func getVulnerabilities(framework, version string) ([]string, []string) {
	entries, exists := knownCVEs[framework]
	if !exists {
		return nil, nil
	}

	var cves []string
	var recommendations []string
	seenRecs := make(map[string]bool)

	for _, entry := range entries {
		for _, affectedVer := range entry.AffectedVersions {
			if version == affectedVer || strings.HasPrefix(version, affectedVer) {
				cves = append(cves, fmt.Sprintf("%s (%s)", entry.CVE, entry.Severity))
				for _, rec := range entry.Recommendations {
					if !seenRecs[rec] {
						recommendations = append(recommendations, rec)
						seenRecs[rec] = true
					}
				}
				break
			}
		}
	}

	return cves, recommendations
}

// getRiskLevel determines overall risk based on detected CVEs
func getRiskLevel(cves []string) string {
	if len(cves) == 0 {
		return "low"
	}
	for _, cve := range cves {
		if strings.Contains(cve, "critical") {
			return "critical"
		}
	}
	for _, cve := range cves {
		if strings.Contains(cve, "high") {
			return "high"
		}
	}
	return "medium"
}

// VersionMatch represents a version detection result with confidence
type VersionMatch struct {
	Version    string
	Confidence float32
	Source     string // where the version was found
}

func extractVersion(body string, framework string) string {
	match := extractVersionOptimized(body, framework)
	return match.Version
}
