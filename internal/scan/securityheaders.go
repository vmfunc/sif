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

package scan

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dropalldatabases/sif/internal/httpx"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/output"
)

type SecurityHeaderResult struct {
	Header   string `json:"header"`
	Present  bool   `json:"present"`
	Value    string `json:"value,omitempty"`
	Severity string `json:"severity"`
	Note     string `json:"note"`
}

type recommendedHeader struct {
	name     string
	severity string
}

var recommendedHeaders = []recommendedHeader{
	{"Strict-Transport-Security", "high"},
	{"Content-Security-Policy", "medium"},
	{"X-Frame-Options", "medium"},
	{"X-Content-Type-Options", "low"},
	{"Referrer-Policy", "low"},
	{"Permissions-Policy", "low"},
	{"Cross-Origin-Opener-Policy", "low"},
}

// headers that leak server/framework details when present.
var disclosureHeaders = []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"}

const hstsMinMaxAge = 31536000 // a year, in seconds

func SecurityHeaders(url string, timeout time.Duration, logdir string) (SecurityHeaderResults, error) {
	log := output.Module("SECHEADERS")
	log.Start()

	sanitizedURL := stripScheme(url)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "Security Header Analysis"); err != nil {
			log.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

	client := httpx.Client(timeout)

	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	results := gradeSecurityHeaders(resp.Header, strings.HasPrefix(url, "https://"))

	for _, r := range results {
		line := r.Header + " " + r.Note
		log.Warn("%s [%s]", line, r.Severity)
		if logdir != "" {
			_ = logger.Write(sanitizedURL, logdir, line+" ["+r.Severity+"]\n")
		}
	}

	if len(results) == 0 {
		log.Success("all recommended security headers present")
	}

	log.Complete(len(results), "issues")
	return results, nil
}

func gradeSecurityHeaders(header http.Header, https bool) SecurityHeaderResults {
	var results SecurityHeaderResults

	for _, h := range recommendedHeaders {
		// hsts does nothing over plain http, so don't flag its absence there
		if h.name == "Strict-Transport-Security" && !https {
			continue
		}

		value := header.Get(h.name)
		switch {
		case value == "":
			results = append(results, SecurityHeaderResult{
				Header:   h.name,
				Severity: h.severity,
				Note:     "missing",
			})
		case h.name == "Strict-Transport-Security" && hstsMaxAge(value) < hstsMinMaxAge:
			results = append(results, SecurityHeaderResult{
				Header:   h.name,
				Present:  true,
				Value:    value,
				Severity: h.severity,
				Note:     "max-age too short",
			})
		case h.name == "X-Content-Type-Options" && !strings.EqualFold(value, "nosniff"):
			results = append(results, SecurityHeaderResult{
				Header:   h.name,
				Present:  true,
				Value:    value,
				Severity: "low",
				Note:     "should be nosniff",
			})
		}
	}

	for _, name := range disclosureHeaders {
		if value := header.Get(name); value != "" {
			results = append(results, SecurityHeaderResult{
				Header:   name,
				Present:  true,
				Value:    value,
				Severity: "low",
				Note:     "discloses " + value,
			})
		}
	}

	return results
}

// hstsMaxAge returns the max-age seconds from an hsts value, or 0 if absent.
func hstsMaxAge(value string) int {
	for _, part := range strings.Split(value, ";") {
		if age, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(part)), "max-age="); ok {
			n, err := strconv.Atoi(strings.TrimSpace(age))
			if err != nil {
				return 0
			}
			return n
		}
	}
	return 0
}
