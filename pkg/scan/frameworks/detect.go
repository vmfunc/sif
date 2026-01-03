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
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/dropalldatabases/sif/pkg/logger"
)

type FrameworkResult struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Confidence  float32  `json:"confidence"`
	CVEs        []string `json:"cves,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
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
		{Pattern: `ASP.NET`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `__VIEWSTATE`, Weight: 0.3},
		{Pattern: `__EVENTVALIDATION`, Weight: 0.3},
		{Pattern: `.aspx`, Weight: 0.2},
	},
	"Spring": {
		{Pattern: `org.springframework`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `spring-security`, Weight: 0.3, HeaderOnly: true},
		{Pattern: `JSESSIONID`, Weight: 0.3, HeaderOnly: true},
		{Pattern: `X-Application-Context`, Weight: 0.3, HeaderOnly: true},
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
	"WordPress": {
		{Pattern: `wp-content`, Weight: 0.4},
		{Pattern: `wp-includes`, Weight: 0.4},
		{Pattern: `wp-json`, Weight: 0.3},
		{Pattern: `wordpress`, Weight: 0.3},
	},
	"Drupal": {
		{Pattern: `Drupal`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `drupal.js`, Weight: 0.4},
		{Pattern: `/sites/default/files`, Weight: 0.3},
		{Pattern: `Drupal.settings`, Weight: 0.3},
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	bodyStr := string(body)

	var bestMatch string
	var highestConfidence float32

	for framework, signatures := range frameworkSignatures {
		var weightedScore float32
		var totalWeight float32

		for _, sig := range signatures {
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

		if confidence > highestConfidence {
			highestConfidence = confidence
			bestMatch = framework
		}
	}

	if highestConfidence > 0 {
		version := detectVersion(bodyStr, bestMatch)
		result := &FrameworkResult{
			Name:       bestMatch,
			Version:    version,
			Confidence: highestConfidence,
		}

		if logdir != "" {
			logger.Write(url, logdir, fmt.Sprintf("Detected framework: %s (version: %s, confidence: %.2f)\n",
				bestMatch, version, highestConfidence))
		}

		frameworklog.Infof("Detected %s framework (version: %s) with %.2f confidence",
			styles.Highlight.Render(bestMatch), version, highestConfidence)

		if cves, suggestions := getVulnerabilities(bestMatch, version); len(cves) > 0 {
			result.CVEs = cves
			result.Suggestions = suggestions
			for _, cve := range cves {
				frameworklog.Warnf("Found potential vulnerability: %s", styles.Highlight.Render(cve))
			}
		}

		return result, nil
	}

	frameworklog.Info("No framework detected")
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
	return extractVersion(body, framework)
}

func getVulnerabilities(framework, version string) ([]string, []string) {
	// TODO: Implement CVE database lookup
	if framework == "Laravel" && version == "8.0.0" {
		return []string{
				"CVE-2021-3129",
			}, []string{
				"Update to Laravel 8.4.2 or later",
				"Implement additional input validation",
			}
	}
	return nil, nil
}

func extractVersion(body string, framework string) string {
	versionPatterns := map[string]string{
		"Laravel":       `Laravel\s+[Vv]?(\d+\.\d+(?:\.\d+)?)`,
		"Django":        `Django[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`,
		"Ruby on Rails": `Rails[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`,
		"Express.js":    `Express[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`,
		"ASP.NET":       `ASP\.NET[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`,
		"Spring":        `Spring[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`,
		"Flask":         `Flask[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`,
		"Next.js":       `Next\.js[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`,
		"Nuxt.js":       `Nuxt[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`,
		"WordPress":     `WordPress[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`,
		"Drupal":        `Drupal[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`,
		"Symfony":       `Symfony[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`,
		"FastAPI":       `FastAPI[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`,
		"Gin":           `Gin[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`,
		"Phoenix":       `Phoenix[/\s]+[Vv]?(\d+\.\d+(?:\.\d+)?)`,
	}

	if pattern, exists := versionPatterns[framework]; exists {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(body)
		if len(matches) > 1 {
			return matches[1]
		}
	}
	return "unknown"
}
