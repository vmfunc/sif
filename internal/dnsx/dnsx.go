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

// Package dnsx resolves subdomain candidates against a bundled resolver pool
// before anything is probed over http, so the slow/inaccurate path of HTTP-ing
// every wordlist entry through the OS resolver is gone. it also fingerprints
// wildcard zones (a zone that answers every random label) so a catch-all
// nameserver can't flood the caller with phantom subdomains.
package dnsx

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"
	"strings"

	retryabledns "github.com/projectdiscovery/retryabledns"
)

// bundled default resolver pool. anycast cloudflare/google/quad9 - fast, public,
// and unlikely to rate-limit a recon sweep. -resolvers overrides this set.
const (
	resolverCloudflare = "1.1.1.1:53"
	resolverGoogle     = "8.8.8.8:53"
	resolverQuad9      = "9.9.9.9:53"
)

// defaultResolvers is the bundled pool used when the caller passes none.
var defaultResolvers = []string{resolverCloudflare, resolverGoogle, resolverQuad9}

const (
	// defaultRetries is how many times retryabledns rotates through the pool on a
	// timeout before giving up on a name. low enough to stay fast on a big list.
	defaultRetries = 3

	// wildcardProbes is how many random nonexistent labels we resolve to
	// fingerprint a wildcard zone. more samples make a rotating catch-all (one
	// that hands back a different ip per query) harder to miss, but each is a
	// real lookup so this stays small.
	wildcardProbes = 3

	// randomLabelLen is the length of each random wildcard-probe label. long
	// enough that a collision with a real host is astronomically unlikely.
	randomLabelLen = 16
)

// randomLabelAlphabet is the lowercase-alnum set wildcard probe labels draw
// from; a valid dns label so the query isn't rejected before it leaves.
const randomLabelAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// defaultDNSPort is appended to any resolver entry given without an explicit
// port, so "1.1.1.1" and "1.1.1.1:53" both work on the cli.
const defaultDNSPort = "53"

// ParseResolvers splits a comma list of resolvers into a normalized slice,
// appending the default port to bare ips/hosts. an empty or blank input returns
// nil so the caller falls back to the bundled pool.
func ParseResolvers(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for i := 0; i < len(parts); i++ {
		entry := strings.TrimSpace(parts[i])
		if entry == "" {
			continue
		}
		// a bare ip/host gets the default port; an entry already carrying ":port"
		// (or a bracketed ipv6 literal) is left as-is.
		if !strings.Contains(entry, ":") {
			entry += ":" + defaultDNSPort
		}
		out = append(out, entry)
	}

	return out
}

// resolution is the resolved address set for one host. empty Addrs means the
// name did not resolve (nxdomain / no records).
type resolution struct {
	Addrs []string
}

// resolved reports whether the name returned any address.
func (r resolution) resolved() bool {
	return len(r.Addrs) > 0
}

// resolverFn is the test seam: every lookup the package makes goes through this
// var, so a fake can answer without touching the network. real runs point it at
// a retryabledns-backed client via NewResolver.
var resolverFn func(host string) (resolution, error)

// Resolver resolves candidates against a pool and filters wildcard answers. it
// is built once per scan and shared across the worker goroutines; the
// underlying retryabledns client is safe for concurrent use.
type Resolver struct {
	// wildcardSigs holds the address sets a wildcard zone answers random labels
	// with. nil/empty means the zone is not wildcard. a candidate whose answer is
	// covered by one of these is a catch-all hit, not a real host.
	wildcardSigs []map[string]struct{}
}

// NewResolver wires resolverFn to a retryabledns client over the given pool
// (bundled default when resolvers is empty) and returns a Resolver. it does not
// fingerprint anything yet - call FingerprintWildcard with the apex first.
func NewResolver(resolvers []string) (*Resolver, error) {
	pool := resolvers
	if len(pool) == 0 {
		pool = defaultResolvers
	}

	client, err := retryabledns.New(pool, defaultRetries)
	if err != nil {
		return nil, fmt.Errorf("dnsx: build resolver over %v: %w", pool, err)
	}

	// only install the real client when a test hasn't already injected a fake;
	// the seam wins so hermetic tests never reach this client.
	if resolverFn == nil {
		resolverFn = func(host string) (resolution, error) {
			data, err := client.Resolve(host)
			if err != nil {
				return resolution{}, fmt.Errorf("dnsx: resolve %q: %w", host, err)
			}
			return resolution{Addrs: mergeAddrs(data)}, nil
		}
	}

	return &Resolver{}, nil
}

// FingerprintWildcard resolves wildcardProbes random labels under apex. any that
// answer mean the zone is a catch-all, so their address sets are recorded as
// signatures to filter real candidates against later. a clean zone leaves the
// signature list empty and nothing gets filtered.
func (r *Resolver) FingerprintWildcard(apex string) error {
	apex = strings.TrimSuffix(apex, ".")
	for i := 0; i < wildcardProbes; i++ {
		label, err := randomLabel(randomLabelLen)
		if err != nil {
			return fmt.Errorf("dnsx: wildcard probe label: %w", err)
		}

		res, err := resolverFn(label + "." + apex)
		if err != nil {
			// a probe failure (timeout / nxdomain surfaced as error) just means this
			// sample says "not wildcard"; don't abort the whole fingerprint on it.
			continue
		}
		if res.resolved() {
			r.wildcardSigs = append(r.wildcardSigs, toSet(res.Addrs))
		}
	}

	return nil
}

// Resolve looks up host and reports whether it is a real, non-wildcard hit. a
// name that doesn't resolve, or whose answer matches a recorded wildcard
// signature, returns false so the caller skips probing it.
func (r *Resolver) Resolve(host string) (bool, error) {
	res, err := resolverFn(host)
	if err != nil {
		return false, fmt.Errorf("dnsx: resolve %q: %w", host, err)
	}
	if !res.resolved() {
		return false, nil
	}
	if r.isWildcard(res.Addrs) {
		return false, nil
	}

	return true, nil
}

// isWildcard reports whether addrs is covered by any recorded wildcard
// signature. a candidate whose every address appears in a wildcard answer is a
// catch-all hit; a host with even one address outside the signature is a real,
// distinct record and survives.
func (r *Resolver) isWildcard(addrs []string) bool {
	if len(r.wildcardSigs) == 0 {
		return false
	}
	for i := 0; i < len(r.wildcardSigs); i++ {
		if subset(addrs, r.wildcardSigs[i]) {
			return true
		}
	}

	return false
}

// mergeAddrs flattens the A and AAAA answers into one sorted, deduped slice so
// two equal answers compare equal regardless of record ordering.
func mergeAddrs(data *retryabledns.DNSData) []string {
	if data == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(data.A)+len(data.AAAA))
	for i := 0; i < len(data.A); i++ {
		seen[data.A[i]] = struct{}{}
	}
	for i := 0; i < len(data.AAAA); i++ {
		seen[data.AAAA[i]] = struct{}{}
	}

	addrs := make([]string, 0, len(seen))
	for addr := range seen {
		addrs = append(addrs, addr)
	}
	sort.Strings(addrs)

	return addrs
}

// toSet turns addrs into a lookup set for subset checks.
func toSet(addrs []string) map[string]struct{} {
	set := make(map[string]struct{}, len(addrs))
	for i := 0; i < len(addrs); i++ {
		set[addrs[i]] = struct{}{}
	}

	return set
}

// subset reports whether every addr is present in sig (and addrs is non-empty);
// an empty addrs can't be a wildcard match.
func subset(addrs []string, sig map[string]struct{}) bool {
	if len(addrs) == 0 {
		return false
	}
	for i := 0; i < len(addrs); i++ {
		if _, ok := sig[addrs[i]]; !ok {
			return false
		}
	}

	return true
}

// randomLabel returns a cryptographically-random lowercase-alnum dns label of
// length n. crypto/rand (not math/rand) so a target can't predict the probe
// labels and special-case them to defeat wildcard detection.
func randomLabel(n int) (string, error) {
	var b strings.Builder
	b.Grow(n)
	alphabetLen := big.NewInt(int64(len(randomLabelAlphabet)))
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, alphabetLen)
		if err != nil {
			return "", fmt.Errorf("dnsx: random index: %w", err)
		}
		b.WriteByte(randomLabelAlphabet[idx.Int64()])
	}

	return b.String(), nil
}
