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

var frameworkSignatures = map[string][]string{
	"Laravel": {
		`laravel_session`,
		`XSRF-TOKEN`,
		`<meta name="csrf-token"`,
	},
	"Django": {
		`csrfmiddlewaretoken`,
		`django.contrib`,
		`django.core`,
		`__admin_media_prefix__`,
	},
	"Ruby on Rails": {
		`csrf-param`,
		`csrf-token`,
		`ruby-on-rails`,
		`rails-env`,
	},
	"Express.js": {
		`express`,
		`connect.sid`,
	},
	"ASP.NET": {
		`ASP.NET`,
		`__VIEWSTATE`,
		`__EVENTVALIDATION`,
	},
	"Spring": {
		`org.springframework`,
		`spring-security`,
		`jsessionid`,
	},
	"Flask": {
		`flask`,
		`werkzeug`,
		`jinja2`,
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
		var matches int
		for _, sig := range signatures {
			if strings.Contains(bodyStr, sig) || containsHeader(resp.Header, sig) {
				matches++
			}
		}

		confidence := float32(matches) / float32(len(signatures))
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

		// Add CVEs and suggestions based on version
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
	patterns := map[string]*regexp.Regexp{
		"Laravel":       regexp.MustCompile(`Laravel[/\s+]?([\d.]+)`),
		"Django":        regexp.MustCompile(`Django/([\d.]+)`),
		"Ruby on Rails": regexp.MustCompile(`Rails/([\d.]+)`),
		"Express.js":    regexp.MustCompile(`express/([\d.]+)`),
		"ASP.NET":       regexp.MustCompile(`ASP\.NET[/\s+]?([\d.]+)`),
		"Spring":        regexp.MustCompile(`spring-(core|framework)/([\d.]+)`),
		"Flask":         regexp.MustCompile(`Flask/([\d.]+)`),
	}

	if pattern, exists := patterns[framework]; exists {
		matches := pattern.FindStringSubmatch(body)
		if len(matches) > 1 {
			return matches[1]
		}
	}
	return "Unknown"
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
