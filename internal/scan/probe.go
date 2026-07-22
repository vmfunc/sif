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
	"html"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
)

// ProbeResult is the httpx-style liveness snapshot for one target: did it answer,
// where did it land, and the few fingerprint fields worth keeping.
type ProbeResult struct {
	URL           string   `json:"url"`
	Alive         bool     `json:"alive"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title,omitempty"`
	Server        string   `json:"server,omitempty"`
	ContentLength int64    `json:"content_length"`
	RedirectChain []string `json:"redirect_chain,omitempty"`
}

// probeMaxRedirects caps the chain we'll follow so a redirect loop can't run
// forever; matches httpx's default depth.
const probeMaxRedirects = 10

// probeMaxBody bounds the body we read to extract a <title> (64KB) so a hostile
// or huge response can't exhaust memory.
const probeMaxBody = 64 * 1024

// titleRe pulls the text out of the first <title>; DOTALL so a title spanning
// lines is still caught.
var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Probe checks whether the target is alive and reports its final status, page
// title, Server header, content-length and the redirect chain it walked.
func Probe(targetURL string, timeout time.Duration, logdir string) (*ProbeResult, error) {
	log := output.Module("PROBE")
	log.Start()

	sanitizedURL := stripScheme(targetURL)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "Live-host probe"); err != nil {
			log.Error("error creating log file: %v", err)
			return nil, fmt.Errorf("create probe log: %w", err)
		}
	}

	// follow redirects but record every hop; the chain is half the value of a
	// probe. capping at probeMaxRedirects stops a loop from spinning forever.
	chain := make([]string, 0, 4)
	client := httpx.Client(timeout)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= probeMaxRedirects {
			return fmt.Errorf("stopped after %d redirects", probeMaxRedirects)
		}
		chain = append(chain, req.URL.String())
		return nil
	}

	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build probe request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		// a transport error means the host didn't answer; that's a dead probe,
		// not a tool failure, so report it rather than bailing.
		log.Warn("%s is dead: %v", output.Highlight.Render(sanitizedURL), err)
		if logdir != "" {
			logger.Write(sanitizedURL, logdir, fmt.Sprintf("dead: %v\n", err))
		}
		result := &ProbeResult{URL: targetURL, Alive: false, RedirectChain: chain}
		log.Complete(0, "alive")
		return result, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, probeMaxBody))
	if err != nil {
		return nil, fmt.Errorf("read probe body: %w", err)
	}

	result := &ProbeResult{
		URL:           targetURL,
		Alive:         true,
		StatusCode:    resp.StatusCode,
		Title:         extractTitle(body),
		Server:        resp.Header.Get("Server"),
		ContentLength: resp.ContentLength,
		RedirectChain: chain,
	}

	log.Info("%s [%s] %s",
		output.Status.Render(fmt.Sprintf("%d", result.StatusCode)),
		output.Highlight.Render(result.Title),
		output.Muted.Render(result.Server))
	if len(chain) > 0 {
		log.Info("redirect chain: %s", strings.Join(chain, " -> "))
	}

	if logdir != "" {
		logger.Write(sanitizedURL, logdir,
			fmt.Sprintf("alive status=%d title=%q server=%q length=%d\n",
				result.StatusCode, result.Title, result.Server, result.ContentLength))
		if len(chain) > 0 {
			logger.Write(sanitizedURL, logdir, "redirect chain: "+strings.Join(chain, " -> ")+"\n")
		}
	}

	log.Complete(1, "alive")
	return result, nil
}

// extractTitle returns the trimmed text of the first <title> in body, or "" when
// there isn't one. html entities are decoded so the title matches the rendered
// page rather than carrying raw "&amp;"-style markup.
func extractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(string(m[1])))
}

// ResultType identifies probe results for the result registry.
func (r *ProbeResult) ResultType() string { return "probe" }

var _ ScanResult = (*ProbeResult)(nil)
