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
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	charmlog "github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/httpx"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/output"
)

// CORSResult collects every cors misconfiguration found on the target.
type CORSResult struct {
	Findings []CORSFinding `json:"findings,omitempty"`
}

// CORSFinding is a single reflecting/permissive cors response.
type CORSFinding struct {
	URL              string `json:"url"`
	OriginTested     string `json:"origin_tested"`
	AllowOrigin      string `json:"allow_origin"`
	AllowCredentials bool   `json:"allow_credentials"`
	Severity         string `json:"severity"`
	Note             string `json:"note"`
}

// the sentinel attacker origin; if it comes back in Access-Control-Allow-Origin
// the target reflects arbitrary origins and any site can read the response.
const corsEvilOrigin = "https://sif-cors-probe.evil.com"

// corsOrigin is a header to inject + why it matters. {host} expands to the
// target host so the prefix/suffix bypasses key off the real name.
var corsOrigins = []struct {
	origin   string // crafted Origin header, {host} -> target host
	note     string // why this case is interesting
	reflects bool   // true when a literal echo of this origin is exploitable
}{
	// arbitrary attacker origin - the classic "reflects anything" bug
	{corsEvilOrigin, "arbitrary origin reflected", true},
	// the literal null origin (sandboxed iframes, redirects, file://) is forgeable
	{"null", "null origin allowed", true},
	// suffix bypass: attacker registers {host}.evil.com, naive endswith checks pass
	{"https://{host}.evil.com", "suffix bypass (attacker subdomain)", true},
	// prefix bypass: attacker registers evil-{host}, naive startswith checks pass
	{"https://evil-{host}", "prefix bypass", true},
	// embedded bypass: {host} appears inside an attacker domain
	{"https://evil.com.{host}", "embedded-host bypass", true},
	// scheme downgrade: http origin trusted lets a mitm read cross-origin data
	{"http://{host}", "http scheme downgrade trusted", true},
}

// CORS probes the target for cross-origin resource sharing misconfigurations.
func CORS(targetURL string, timeout time.Duration, threads int, logdir string) (*CORSResult, error) {
	log := output.Module("CORS")
	log.Start()

	spin := output.NewSpinner("Scanning for CORS misconfigurations")
	spin.Start()

	sanitizedURL := stripScheme(targetURL)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "CORS misconfiguration probe"); err != nil {
			spin.Stop()
			log.Error("error creating log file: %v", err)
			return nil, fmt.Errorf("create cors log: %w", err)
		}
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		spin.Stop()
		return nil, fmt.Errorf("parse url: %w", err)
	}
	host := parsedURL.Host

	client := httpx.Client(timeout)
	// don't follow redirects: cors is judged on the host we asked about, so a
	// bounce to a permissive third party can't be pinned on the target.
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	result := &CORSResult{Findings: make([]CORSFinding, 0, len(corsOrigins))}

	var mu sync.Mutex
	var wg sync.WaitGroup

	// one origin per worker item; the set is small so a buffered channel is plenty
	originChan := make(chan int, len(corsOrigins))
	for i := 0; i < len(corsOrigins); i++ {
		originChan <- i
	}
	close(originChan)

	wg.Add(threads)
	for t := 0; t < threads; t++ {
		go func() {
			defer wg.Done()
			for idx := range originChan {
				spec := corsOrigins[idx]
				// {host} is the seam that turns a template into a real attacker origin
				origin := strings.ReplaceAll(spec.origin, "{host}", host)

				finding, ok := probeCORS(client, targetURL, origin, spec.note)
				if !ok {
					continue
				}

				mu.Lock()
				result.Findings = append(result.Findings, finding)
				mu.Unlock()

				spin.Stop()
				log.Warn("cors %s: origin %s reflected (creds=%t)",
					renderCORSSeverity(finding.Severity),
					output.Highlight.Render(origin),
					finding.AllowCredentials)
				spin.Start()

				if logdir != "" {
					logger.Write(sanitizedURL, logdir,
						fmt.Sprintf("CORS: %s - origin [%s] reflected as [%s] creds=%t\n",
							finding.Note, origin, finding.AllowOrigin, finding.AllowCredentials))
				}
			}
		}()
	}
	wg.Wait()

	spin.Stop()

	if len(result.Findings) == 0 {
		log.Info("no cors misconfigurations detected")
		log.Complete(0, "found")
		return nil, nil //nolint:nilnil // no finding is not an error, mirrors the other scanners
	}

	log.Complete(len(result.Findings), "found")
	return result, nil
}

// probeCORS sends one request with the crafted Origin and decides whether the
// response trusts it. It returns the finding and true only when the server
// reflects the origin (or "null"/"*" with credentials), which is the exploitable
// shape - a server that ignores Origin or returns its own host is fine.
func probeCORS(client *http.Client, targetURL, origin, note string) (CORSFinding, bool) {
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		charmlog.Debugf("cors: build request for %s: %v", targetURL, err)
		return CORSFinding{}, false
	}
	req.Header.Set("Origin", origin)

	resp, err := client.Do(req) //nolint:bodyclose // drained and closed via httpx.DrainClose
	if err != nil {
		charmlog.Debugf("cors: request %s with origin %s: %v", targetURL, origin, err)
		return CORSFinding{}, false
	}
	// headers are all we need; drain the body so the conn returns to the pool.
	httpx.DrainClose(resp)

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	if allowOrigin == "" {
		return CORSFinding{}, false
	}

	allowCreds := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")

	// a wildcard with credentials is forbidden by browsers, so it isn't directly
	// exploitable; a plain wildcard exposes only public data. neither is a finding.
	if allowOrigin == "*" {
		return CORSFinding{}, false
	}

	// the bug is reflection: the server echoed our attacker origin back. if it
	// returned something else (its own host) it isn't trusting us.
	reflected := allowOrigin == origin

	if !reflected {
		return CORSFinding{}, false
	}

	return CORSFinding{
		URL:              targetURL,
		OriginTested:     origin,
		AllowOrigin:      allowOrigin,
		AllowCredentials: allowCreds,
		Severity:         corsSeverity(allowCreds),
		Note:             note,
	}, true
}

// corsSeverity ranks the finding: reflection + credentials lets an attacker read
// authenticated responses, which is the high-impact case.
func corsSeverity(allowCreds bool) string {
	if allowCreds {
		return "high"
	}
	return "medium"
}

func renderCORSSeverity(severity string) string {
	if severity == "high" {
		return output.SeverityHigh.Render(severity)
	}
	return output.SeverityMedium.Render(severity)
}

// ResultType identifies cors findings for the result registry.
func (r *CORSResult) ResultType() string { return "cors" }

var _ ScanResult = (*CORSResult)(nil)
