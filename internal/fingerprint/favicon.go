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

// Package fingerprint holds small response-fingerprinting primitives shared by
// the scan checks and the module engine, so both compute identical values.
package fingerprint

import (
	"encoding/base64"
	"strings"

	"github.com/twmb/murmur3"
)

// b64LineLen is python's base64.encodebytes line width. mmh3/shodan hash the
// chunked base64 (newline every 76 chars, trailing newline), so we must wrap at
// exactly this width to land on the same hash.
const b64LineLen = 76

// FaviconHash computes shodan's favicon hash: murmur3 32-bit over the python
// base64.encodebytes encoding of the raw icon (newline every 76 chars plus a
// trailing newline), reinterpreted as a signed int32 (both load-bearing, golden-pinned).
func FaviconHash(data []byte) int32 {
	encoded := encodeFaviconBase64(data)
	return int32(murmur3.Sum32(encoded)) //nolint:gosec // shodan stores the signed reinterpretation on purpose
}

// faviconTech maps a known shodan favicon hash to the tech that ships it.
// these are stable default icons for panels/frameworks/c2; a hit is a strong
// fingerprint. kept small on purpose - high-signal defaults, not an exhaustive db.
var faviconTech = map[int32]string{
	116323821:   "Apache Tomcat",
	81586312:    "Spring Boot (default whitelabel)",
	-235701012:  "Jenkins",
	-1255347784: "GitLab",
	1278322581:  "Grafana",
	743365239:   "Kibana",
	-1462443472: "phpMyAdmin",
	999357577:   "Cobalt Strike (default beacon)",
	-1521704893: "Metasploit",
	// gitea reskinned its default icon twice, so one hash does not cover the
	// deployed population. each of these is public/assets/img/favicon.png at the
	// tagged release, hashed with FaviconHash above:
	//   -754147112  4351 bytes  v1.15 through v1.24
	//   -1668137428 4335 bytes  v1.25 onward, confirmed live against
	//               gitea.com (1.27.0+dev) and demo.gitea.com (1.28.0+dev)
	// pre-v1.15 icons (v1.4-v1.8, v1.9-v1.12, v1.13) are left out; those
	// releases are long EOL and the table stays high-signal defaults only.
	-754147112:  "Gitea",
	-1668137428: "Gitea",
	-1893514588: "Gitea",
}

// LookupFaviconTech returns the tech that ships the given shodan favicon hash and
// whether the hash is known.
func LookupFaviconTech(hash int32) (string, bool) {
	tech, ok := faviconTech[hash]
	return tech, ok
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
