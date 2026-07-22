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

	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
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
	resp, err := client.Do(req) //nolint:bodyclose // drained and closed via httpx.DrainClose
	if err != nil {
		return nil, err
	}
	// header-only scan: drain on close so the conn is returned to the pool.
	defer httpx.DrainClose(resp)

	results := gradeSecurityHeaders(resp.Header, responseIsHTTPS(resp, url))

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

// responseIsHTTPS reports whether the response was actually served over
// https. the client follows redirects, so a request that started as
// http:// can end up served over https:// (or vice versa); the final
// scheme lives on resp.Request.URL, not the originally requested url.
// falls back to the requested url's scheme if that's unavailable.
func responseIsHTTPS(resp *http.Response, requestedURL string) bool {
	if resp != nil && resp.Request != nil && resp.Request.URL != nil {
		return resp.Request.URL.Scheme == "https"
	}
	return strings.HasPrefix(requestedURL, "https://")
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
			// rfc 6797 allows a quoted-string value
			age = strings.Trim(strings.TrimSpace(age), `"`)
			n, err := strconv.Atoi(age)
			if err != nil {
				return 0
			}
			return n
		}
	}
	return 0
}
