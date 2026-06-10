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
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dropalldatabases/sif/internal/httpx"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/output"
	"github.com/spaolacci/murmur3"
)

// FaviconResult is the computed shodan-style favicon hash plus the pivot query
// and any matched tech.
type FaviconResult struct {
	FaviconURL string `json:"favicon_url"` // where the icon was fetched
	Hash       int32  `json:"hash"`        // shodan mmh3 hash (signed int32)
	Tech       string `json:"tech"`        // matched technology, empty when unknown
	ShodanQ    string `json:"shodan_query"`
}

// faviconBodyReadCap bounds the icon read. real favicons are tens of kilobytes;
// a megabyte ceiling covers oversized ones without letting a hostile endpoint
// stream forever.
const faviconBodyReadCap = 1 << 20

// b64LineLen is python's base64.encodebytes line width. mmh3/shodan hash the
// chunked base64 (newline every 76 chars, trailing newline), so we must wrap at
// exactly this width to land on the same hash.
const b64LineLen = 76

// faviconLinkRegex pulls the href off a <link rel="...icon..."> tag so we can
// fall back to a declared icon when /favicon.ico is absent.
var faviconLinkRegex = regexp.MustCompile(`(?i)<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]*>`)

// faviconHrefRegex extracts the href attribute value from a matched link tag.
var faviconHrefRegex = regexp.MustCompile(`(?i)href=["']([^"']+)["']`)

// faviconHashes maps a known shodan favicon hash to the tech that ships it.
// these are stable default icons for panels/frameworks/c2; a hit is a strong
// fingerprint. kept small on purpose - high-signal defaults, not an exhaustive db.
var faviconHashes = map[int32]string{
	116323821:   "Apache Tomcat",
	81586312:    "Spring Boot (default whitelabel)",
	-235701012:  "Jenkins",
	-1255347784: "GitLab",
	1278322581:  "Grafana",
	743365239:   "Kibana",
	-1462443472: "phpMyAdmin",
	999357577:   "Cobalt Strike (default beacon)",
	-1521704893: "Metasploit",
	-1893514588: "Gitea",
}

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

	hash := FaviconHash(data)
	result := &FaviconResult{
		FaviconURL: iconURL,
		Hash:       hash,
		Tech:       faviconHashes[hash],
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
	iconURL := base + "/favicon.ico"
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

// getFaviconBytes GETs an icon url and returns the body, erroring on a non-200 or
// an empty body so a soft-404 html page isn't hashed as if it were an icon.
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, faviconBodyReadCap))
	if err != nil {
		return nil, fmt.Errorf("read favicon: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty favicon body")
	}
	return data, nil
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, faviconBodyReadCap))
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
// the target base. an absolute href is returned as-is.
func resolveFaviconURL(base, href string) string {
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}
	if strings.HasPrefix(href, "//") {
		// scheme-relative; inherit the base scheme.
		scheme := "https:"
		if strings.HasPrefix(base, "http://") {
			scheme = "http:"
		}
		return scheme + href
	}
	if strings.HasPrefix(href, "/") {
		return base + href
	}
	return base + "/" + href
}

// FaviconHash computes shodan's favicon hash: murmur3 32-bit over the python
// base64.encodebytes encoding of the raw icon (newline every 76 chars plus a
// trailing newline), reinterpreted as a signed int32. the chunking and the sign
// are both load-bearing - shodan stores the value python's mmh3.hash() returns,
// which is signed, over the wrapped base64, not the raw bytes. the golden test
// pins this exactly.
func FaviconHash(data []byte) int32 {
	encoded := encodeFaviconBase64(data)
	return int32(murmur3.Sum32(encoded)) //nolint:gosec // shodan stores the signed reinterpretation on purpose
}

// encodeFaviconBase64 mirrors python's base64.encodebytes: standard base64 with
// a newline inserted every 76 output characters and a trailing newline. this is
// the exact byte stream shodan feeds to mmh3, so it must match byte-for-byte.
func encodeFaviconBase64(data []byte) []byte {
	raw := base64.StdEncoding.EncodeToString(data)

	var b strings.Builder
	// final size: the base64 body plus one '\n' per (full or partial) 76-char
	// line. preallocate so the builder never regrows mid-loop.
	b.Grow(len(raw) + len(raw)/b64LineLen + 1)
	for i := 0; i < len(raw); i += b64LineLen {
		end := i + b64LineLen
		if end > len(raw) {
			end = len(raw)
		}
		b.WriteString(raw[i:end])
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// ResultType identifies favicon findings for the result registry.
func (r *FaviconResult) ResultType() string { return "favicon" }

var _ ScanResult = (*FaviconResult)(nil)
