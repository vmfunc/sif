package frameworks

import (
	"fmt"
	"io"
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
		{Pattern: `django.contrib`, Weight: 0.3},
		{Pattern: `django.core`, Weight: 0.3},
		{Pattern: `__admin_media_prefix__`, Weight: 0.3},
	},
	"Ruby on Rails": {
		{Pattern: `csrf-param`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `csrf-token`, Weight: 0.3, HeaderOnly: true},
		{Pattern: `ruby-on-rails`, Weight: 0.3},
		{Pattern: `rails-env`, Weight: 0.3},
	},
	"Express.js": {
		{Pattern: `express`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `connect.sid`, Weight: 0.3, HeaderOnly: true},
	},
	"ASP.NET": {
		{Pattern: `ASP.NET`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `__VIEWSTATE`, Weight: 0.3},
		{Pattern: `__EVENTVALIDATION`, Weight: 0.3},
	},
	"Spring": {
		{Pattern: `org.springframework`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `spring-security`, Weight: 0.3, HeaderOnly: true},
		{Pattern: `jsessionid`, Weight: 0.3, HeaderOnly: true},
	},
	"Flask": {
		{Pattern: `flask`, Weight: 0.4, HeaderOnly: true},
		{Pattern: `werkzeug`, Weight: 0.3, HeaderOnly: true},
		{Pattern: `jinja2`, Weight: 0.3},
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

		confidence := float32(1.0 / (1.0 + exp(-float64(weightedScore/totalWeight)*6.0)))

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
	for _, values := range headers {
		for _, value := range values {
			if strings.Contains(strings.ToLower(value), strings.ToLower(signature)) {
				return true
			}
		}
	}
	return false
}

func detectVersion(body string, framework string) string {
	version := extractVersion(body, framework)
	if version == "Unknown" {
		return version
	}

	parts := strings.Split(version, ".")
	var normalized string
	if len(parts) >= 3 {
		normalized = fmt.Sprintf("%05s.%05s.%05s", parts[0], parts[1], parts[2])
	}
	return normalized
}

func exp(x float64) float64 {
	if x > 88.0 {
		return 1e38
	}
	if x < -88.0 {
		return 0
	}

	sum := 1.0
	term := 1.0
	for i := 1; i <= 20; i++ {
		term *= x / float64(i)
		sum += term
	}
	return sum
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
		"Laravel":       `Laravel\s+[Vv]?(\d+\.\d+\.\d+)`,
		"Django":        `Django\s+[Vv]?(\d+\.\d+\.\d+)`,
		"Ruby on Rails": `Rails\s+[Vv]?(\d+\.\d+\.\d+)`,
		"Express.js":    `Express\s+[Vv]?(\d+\.\d+\.\d+)`,
		"ASP.NET":       `ASP\.NET\s+[Vv]?(\d+\.\d+\.\d+)`,
		"Spring":        `Spring\s+[Vv]?(\d+\.\d+\.\d+)`,
		"Flask":         `Flask\s+[Vv]?(\d+\.\d+\.\d+)`,
	}

	if pattern, exists := versionPatterns[framework]; exists {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(body)
		if len(matches) > 1 {
			return matches[1]
		}
	}
	return "Unknown"
}
