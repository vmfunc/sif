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
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/vmfunc/sif/internal/fingerprint"
	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
)

// FaviconResult is the computed shodan-style favicon hash plus the pivot query
// and any matched tech.
type FaviconResult struct {
	FaviconURL string `json:"favicon_url"` // where the icon was fetched
	Hash       int32  `json:"hash"`        // shodan mmh3 hash (signed int32)
	Tech       string `json:"tech"`        // matched technology, empty when unknown
	ShodanQ    string `json:"shodan_query"`
}

// faviconLinkRegex pulls the href off a <link rel="...icon..."> tag so we can
// fall back to a declared icon when /favicon.ico is absent.
var faviconLinkRegex = regexp.MustCompile(`(?i)<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]*>`)

// faviconHrefRegex extracts the href attribute value from a matched link tag.
var faviconHrefRegex = regexp.MustCompile(`(?i)href=["']([^"']+)["']`)

// Favicon fetches the target's favicon, computes the shodan mmh3 hash and matches
// it against the bundled fingerprint map.
func Favicon(targetURL string, timeout time.Duration, logdir string) (*FaviconResult, error) {
	log := output.Module("FAVICON")
	log.Start()

	sanitizedURL := stripScheme(targetURL)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "Favicon hash fingerprint"); err != nil {
			log.Error("error creating log file: %v", err)
			return nil, fmt.Errorf("create favicon log: %w", err)
		}
	}

	client := httpx.Client(timeout)
	base := strings.TrimRight(targetURL, "/")

	iconURL, data, err := fetchFavicon(client, base)
	if err != nil {
		log.Info("no favicon found: %v", err)
		log.Complete(0, "found")
		return nil, nil //nolint:nilnil // a missing favicon is not an error
	}

	hash := fingerprint.FaviconHash(data)
	tech, _ := fingerprint.LookupFaviconTech(hash)
	result := &FaviconResult{
		FaviconURL: iconURL,
		Hash:       hash,
		Tech:       tech,
		ShodanQ:    fmt.Sprintf("http.favicon.hash:%d", hash),
	}

	if result.Tech != "" {
		log.Warn("favicon hash %d matches %s", hash, output.Highlight.Render(result.Tech))
	} else {
		log.Info("favicon hash %d (no fingerprint match)", hash)
	}
	log.Info("shodan pivot: %s", output.Highlight.Render(result.ShodanQ))

	if logdir != "" {
		_ = logger.Write(sanitizedURL, logdir,
			fmt.Sprintf("Favicon %s hash=%d tech=%q query=%s\n", iconURL, hash, result.Tech, result.ShodanQ))
	}

	log.Complete(1, "hashed")
	return result, nil
}

// fetchFavicon tries /favicon.ico first, then the <link rel=icon> declared in the
// homepage html. it returns the url it pulled the bytes from so the report shows
// exactly which icon was hashed.
func fetchFavicon(client *http.Client, base string) (string, []byte, error) {
	// the well-known icon always lives at the origin root, so resolve it there
	// rather than appending to a target that may carry a path.
	iconURL := resolveFaviconURL(base, "/favicon.ico")
	if data, err := getFaviconBytes(client, iconURL); err == nil {
		return iconURL, data, nil
	}

	// no /favicon.ico; parse the homepage for a declared icon link.
	href, err := declaredFaviconHref(client, base)
	if err != nil {
		return "", nil, err
	}
	iconURL = resolveFaviconURL(base, href)
	data, err := getFaviconBytes(client, iconURL)
	if err != nil {
		return "", nil, err
	}
	return iconURL, data, nil
}

// getFaviconBytes GETs an icon url and returns the body, erroring on a non-200,
// an empty body, or one that doesn't look like an image. many apps answer a
// missing icon with a 200 html "not found" page rather than a real 404, and
// that page must not be hashed as if it were the icon.
func getFaviconBytes(client *http.Client, iconURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, iconURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build favicon request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch favicon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("favicon status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, httpx.MaxBodySize))
	if err != nil {
		return nil, fmt.Errorf("read favicon: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty favicon body")
	}
	if !looksLikeImage(resp.Header.Get("Content-Type"), data) {
		return nil, fmt.Errorf("favicon body at %s is not image content", iconURL)
	}
	return data, nil
}

// faviconMagic is the set of byte-signature prefixes real icon formats start
// with, checked when the Content-Type header doesn't already say image/*.
var faviconMagic = [][]byte{
	{0x00, 0x00, 0x01, 0x00}, // ICO
	{0x89, 0x50, 0x4E, 0x47}, // PNG
	[]byte("GIF8"),           // GIF
	{0xFF, 0xD8, 0xFF},       // JPEG
	[]byte("RIFF"),           // WEBP (also needs "WEBP" at offset 8, checked below)
}

// looksLikeImage reports whether a response should be treated as an icon: an
// image/* Content-Type is trusted outright, otherwise the body is sniffed
// against known icon/image magic bytes.
func looksLikeImage(contentType string, body []byte) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = ct[:idx]
	}
	if strings.HasPrefix(ct, "image/") {
		return true
	}

	for _, magic := range faviconMagic {
		if bytes.HasPrefix(body, magic) {
			if string(magic) == "RIFF" {
				return len(body) >= 12 && string(body[8:12]) == "WEBP"
			}
			return true
		}
	}

	trimmed := bytes.TrimSpace(body)
	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(bytes.ToLower(trimmed), []byte("<svg")) {
		return true
	}
	return false
}

// declaredFaviconHref fetches the homepage and extracts the href of the first
// <link rel="...icon..."> tag.
func declaredFaviconHref(client *http.Client, base string) (string, error) {
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, base, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("build homepage request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch homepage: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, httpx.MaxBodySize))
	if err != nil {
		return "", fmt.Errorf("read homepage: %w", err)
	}

	link := faviconLinkRegex.Find(body)
	if link == nil {
		return "", fmt.Errorf("no favicon link in homepage")
	}
	href := faviconHrefRegex.FindSubmatch(link)
	if href == nil {
		return "", fmt.Errorf("favicon link has no href")
	}
	return string(href[1]), nil
}

// resolveFaviconURL turns a possibly-relative href into an absolute url against
// the target base, browser-style (root-relative anchors at the origin, not the
// target's path). unparsable input falls back to the raw href.
func resolveFaviconURL(base, href string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return href
	}
	ref, err := url.Parse(href)
	if err != nil {
		return href
	}
	return baseURL.ResolveReference(ref).String()
}

// ResultType identifies favicon findings for the result registry.
func (r *FaviconResult) ResultType() string { return "favicon" }

var _ ScanResult = (*FaviconResult)(nil)
