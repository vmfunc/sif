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

// CVEEntry represents a known vulnerability for a framework version
type CVEEntry struct {
	CVE              string
	AffectedVersions []string // versions affected (use semver ranges in future)
	FixedVersion     string
	Severity         string // critical, high, medium, low
	Description      string
	Recommendations  []string
}

// knownCVEs contains known vulnerabilities for popular frameworks.
// This database can be extended or loaded from an external source.
var knownCVEs = map[string][]CVEEntry{
	"Laravel": {
		{
			CVE:              "CVE-2021-3129",
			AffectedVersions: []string{"8.0.0", "8.0.1", "8.0.2", "8.1.0", "8.2.0", "8.3.0", "8.4.0", "8.4.1"},
			FixedVersion:     "8.4.2",
			Severity:         "critical",
			Description:      "Ignition debug mode RCE vulnerability",
			Recommendations:  []string{"Update to Laravel 8.4.2 or later", "Disable debug mode in production"},
		},
		{
			CVE:              "CVE-2021-21263",
			AffectedVersions: []string{"8.0.0", "8.1.0", "8.2.0", "8.3.0", "8.4.0"},
			FixedVersion:     "8.5.0",
			Severity:         "high",
			Description:      "SQL injection via request validation",
			Recommendations:  []string{"Update to Laravel 8.5.0 or later", "Use parameterized queries"},
		},
	},
	"Django": {
		{
			CVE:              "CVE-2023-36053",
			AffectedVersions: []string{"3.2.0", "3.2.1", "3.2.2", "4.0.0", "4.1.0"},
			FixedVersion:     "4.2.3",
			Severity:         "high",
			Description:      "Potential ReDoS in EmailValidator and URLValidator",
			Recommendations:  []string{"Update to Django 4.2.3 or later"},
		},
		{
			CVE:              "CVE-2023-31047",
			AffectedVersions: []string{"3.2.0", "4.0.0", "4.1.0"},
			FixedVersion:     "4.1.9",
			Severity:         "medium",
			Description:      "File upload validation bypass",
			Recommendations:  []string{"Update to Django 4.1.9 or later", "Implement additional file validation"},
		},
	},
	"WordPress": {
		{
			CVE:              "CVE-2023-2745",
			AffectedVersions: []string{"5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8", "5.9", "6.0", "6.1"},
			FixedVersion:     "6.2",
			Severity:         "medium",
			Description:      "Directory traversal vulnerability",
			Recommendations:  []string{"Update to WordPress 6.2 or later"},
		},
	},
	"Drupal": {
		{
			CVE:              "CVE-2023-44487",
			AffectedVersions: []string{"9.0", "9.1", "9.2", "9.3", "9.4", "9.5", "10.0"},
			FixedVersion:     "10.1.4",
			Severity:         "high",
			Description:      "HTTP/2 rapid reset attack (DoS)",
			Recommendations:  []string{"Update to Drupal 10.1.4 or later", "Configure HTTP/2 rate limiting"},
		},
	},
	"Next.js": {
		{
			CVE:              "CVE-2023-46298",
			AffectedVersions: []string{"13.0.0", "13.1.0", "13.2.0", "13.3.0", "13.4.0"},
			FixedVersion:     "13.5.0",
			Severity:         "medium",
			Description:      "Server-side request forgery vulnerability",
			Recommendations:  []string{"Update to Next.js 13.5.0 or later"},
		},
	},
	"Angular": {
		{
			CVE:              "CVE-2023-26117",
			AffectedVersions: []string{"14.0.0", "14.1.0", "14.2.0", "15.0.0"},
			FixedVersion:     "15.2.0",
			Severity:         "medium",
			Description:      "Regular expression denial of service",
			Recommendations:  []string{"Update to Angular 15.2.0 or later"},
		},
	},
	"Vue.js": {
		{
			CVE:              "CVE-2024-5987",
			AffectedVersions: []string{"2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0", "2.5.0", "2.6.0"},
			FixedVersion:     "2.7.16",
			Severity:         "medium",
			Description:      "XSS vulnerability in certain configurations",
			Recommendations:  []string{"Update to Vue.js 2.7.16 or 3.x"},
		},
	},
	"Express.js": {
		{
			CVE:              "CVE-2024-29041",
			AffectedVersions: []string{"4.0.0", "4.1.0", "4.2.0", "4.3.0", "4.4.0"},
			FixedVersion:     "4.19.2",
			Severity:         "medium",
			Description:      "Open redirect vulnerability",
			Recommendations:  []string{"Update to Express.js 4.19.2 or later"},
		},
	},
	"Ruby on Rails": {
		{
			CVE:              "CVE-2023-22795",
			AffectedVersions: []string{"6.0.0", "6.1.0", "7.0.0"},
			FixedVersion:     "7.0.4.1",
			Severity:         "high",
			Description:      "ReDoS vulnerability in Action Dispatch",
			Recommendations:  []string{"Update to Rails 7.0.4.1 or later"},
		},
	},
	"Spring": {
		{
			CVE:              "CVE-2022-22965",
			AffectedVersions: []string{"5.0.0", "5.1.0", "5.2.0", "5.3.0"},
			FixedVersion:     "5.3.18",
			Severity:         "critical",
			Description:      "Spring4Shell RCE vulnerability",
			Recommendations:  []string{"Update to Spring 5.3.18 or later", "Disable class binding on user input"},
		},
	},
	"Spring Boot": {
		{
			CVE:              "CVE-2022-22963",
			AffectedVersions: []string{"2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.4.0", "2.5.0", "2.6.0"},
			FixedVersion:     "2.6.6",
			Severity:         "critical",
			Description:      "RCE via Spring Cloud Function",
			Recommendations:  []string{"Update to Spring Boot 2.6.6 or later"},
		},
	},
	"ASP.NET": {
		{
			CVE:              "CVE-2023-36899",
			AffectedVersions: []string{"4.0", "4.5", "4.6", "4.7", "4.8"},
			FixedVersion:     "latest security patches",
			Severity:         "high",
			Description:      "Elevation of privilege vulnerability",
			Recommendations:  []string{"Apply latest security patches", "Ensure proper request validation"},
		},
	},
	"Joomla": {
		{
			CVE:              "CVE-2023-23752",
			AffectedVersions: []string{"4.0.0", "4.1.0", "4.2.0"},
			FixedVersion:     "4.2.8",
			Severity:         "critical",
			Description:      "Improper access check allowing unauthorized access to webservice endpoints",
			Recommendations:  []string{"Update to Joomla 4.2.8 or later"},
		},
	},
	"Magento": {
		{
			CVE:              "CVE-2022-24086",
			AffectedVersions: []string{"2.3.0", "2.3.1", "2.3.2", "2.4.0", "2.4.1", "2.4.2"},
			FixedVersion:     "2.4.3-p1",
			Severity:         "critical",
			Description:      "Improper input validation leading to arbitrary code execution",
			Recommendations:  []string{"Update to Magento 2.4.3-p1 or later"},
		},
	},
}
