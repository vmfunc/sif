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

package js

import (
	"net/url"
	"regexp"
	"slices"
	"strings"

	urlutil "github.com/projectdiscovery/utils/url"
)

// endpointRegex is a linkfinder-style matcher for quoted paths and urls inside
// js: full http(s) urls, root-relative (/api/...) and dotted-relative paths,
// plus bare api-ish words with an extension. the inner alternation lives in a
// single capture group so FindAllStringSubmatch hands back just the value.
var endpointRegex = regexp.MustCompile(`["'\x60]` +
	`(` +
	`(?:https?:)?//[^\s"'\x60]{2,}` + // protocol-relative or absolute url
	`|` +
	`/[A-Za-z0-9_\-./]+(?:\?[^\s"'\x60]*)?` + // root-relative path
	`|` +
	`\.{1,2}/[A-Za-z0-9_\-./]+(?:\?[^\s"'\x60]*)?` + // dotted-relative path
	`)` +
	`["'\x60]`)

// shortest thing we'll treat as an endpoint; below this it's almost always
// noise like "/" or a single slash-prefixed letter.
const minEndpointLen = 3

// mime types slip through the path regex (text/html, application/json, ...) but
// are never endpoints, so they're filtered out by their top-level type.
var mimePrefixes = []string{
	"text/", "image/", "audio/", "video/", "font/",
	"application/", "multipart/", "model/", "message/",
}

// ExtractEndpoints pulls candidate paths and urls out of a script body, dedupes
// them, drops obvious noise, and resolves relatives against baseURL so callers
// get absolute targets where possible. a baseURL that won't parse just leaves
// relatives as-is rather than failing the whole scan.
func ExtractEndpoints(content, baseURL string) []string {
	groups := endpointRegex.FindAllStringSubmatch(content, -1)
	if len(groups) == 0 {
		return nil
	}

	base, baseErr := urlutil.Parse(baseURL)

	endpoints := make([]string, 0, len(groups))
	seen := make(map[string]struct{}, len(groups))
	for i := 0; i < len(groups); i++ {
		candidate := strings.TrimSpace(groups[i][1])
		if !isEndpoint(candidate) {
			continue
		}

		resolved := candidate
		// only relatives need resolving, and only if the base parsed cleanly.
		if baseErr == nil && base.URL != nil && isRelative(candidate) {
			resolved = resolveRelative(base.URL, candidate)
		}

		if _, ok := seen[resolved]; ok {
			continue
		}
		seen[resolved] = struct{}{}
		endpoints = append(endpoints, resolved)
	}

	slices.Sort(endpoints)
	return endpoints
}

// isEndpoint filters out the junk that the broad regex inevitably catches:
// too-short fragments, mime types, and single dotted words with no path.
func isEndpoint(s string) bool {
	if len(s) < minEndpointLen {
		return false
	}

	lower := strings.ToLower(s)
	for i := 0; i < len(mimePrefixes); i++ {
		// a mime type is "type/subtype" with no further path; an api route like
		// /application/users has a leading slash, so anchor on the bare prefix.
		if strings.HasPrefix(lower, mimePrefixes[i]) && !strings.HasPrefix(lower, "/") {
			return false
		}
	}

	// reject "word" or "a.b" with no slash at all: not a path, just a token.
	if !strings.Contains(s, "/") {
		return false
	}

	return true
}

// isRelative reports whether candidate lacks a scheme/host and so needs the
// base url to become absolute. protocol-relative (//host) and absolute urls
// are left untouched.
func isRelative(candidate string) bool {
	if strings.HasPrefix(candidate, "//") {
		return false
	}
	return !strings.HasPrefix(candidate, "http://") && !strings.HasPrefix(candidate, "https://")
}

// resolveRelative turns a relative path into an absolute url against base using
// the stdlib reference resolver; if the ref won't parse we keep the original.
func resolveRelative(base *url.URL, ref string) string {
	parsed, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return base.ResolveReference(parsed).String()
}
