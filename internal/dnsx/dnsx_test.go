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

package dnsx

import (
	"reflect"
	"strings"
	"testing"
)

// withFakeResolver swaps resolverFn for fn for the duration of one test, then
// restores it - the seam that keeps every case below network-free.
func withFakeResolver(t *testing.T, fn func(host string) (resolution, error)) {
	t.Helper()
	orig := resolverFn
	resolverFn = fn
	t.Cleanup(func() { resolverFn = orig })
}

// newFingerprinted builds a Resolver and runs the wildcard fingerprint against
// apex using the already-injected fake; fatal on error.
func newFingerprinted(t *testing.T, apex string) *Resolver {
	t.Helper()
	r := &Resolver{}
	if err := r.FingerprintWildcard(apex); err != nil {
		t.Fatalf("FingerprintWildcard: %v", err)
	}

	return r
}

const testApex = "example.com"

// a host that resolves to a real address, in a clean (non-wildcard) zone, is a
// genuine hit.
func TestResolve_FoundInCleanZone(t *testing.T) {
	withFakeResolver(t, func(host string) (resolution, error) {
		// nothing answers a random wildcard probe -> clean zone.
		if strings.HasSuffix(host, "."+testApex) && host != "www."+testApex {
			return resolution{}, nil
		}
		if host == "www."+testApex {
			return resolution{Addrs: []string{"93.184.216.34"}}, nil
		}
		return resolution{}, nil
	})

	r := newFingerprinted(t, testApex)
	if len(r.wildcardSigs) != 0 {
		t.Fatalf("clean zone should record no wildcard signatures, got %d", len(r.wildcardSigs))
	}

	ok, err := r.Resolve("www." + testApex)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !ok {
		t.Error("a resolving host in a clean zone should be a hit")
	}
}

// nxdomain (no addresses) is not a hit, so the caller skips probing it.
func TestResolve_NxdomainSkipped(t *testing.T) {
	withFakeResolver(t, func(string) (resolution, error) {
		// every name, probes included, returns no records.
		return resolution{}, nil
	})

	r := newFingerprinted(t, testApex)

	ok, err := r.Resolve("ghost." + testApex)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ok {
		t.Error("an nxdomain host must not count as found")
	}
}

// a wildcard zone answers the random probe labels, so a candidate that resolves
// to the same catch-all address is filtered out.
func TestResolve_WildcardFiltered(t *testing.T) {
	const catchAll = "10.0.0.1"
	withFakeResolver(t, func(string) (resolution, error) {
		// the zone answers everything - probes and candidates alike - with one ip.
		return resolution{Addrs: []string{catchAll}}, nil
	})

	r := newFingerprinted(t, testApex)
	if len(r.wildcardSigs) == 0 {
		t.Fatal("wildcard zone should record at least one signature")
	}

	ok, err := r.Resolve("anything." + testApex)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ok {
		t.Error("a candidate matching the wildcard answer must be filtered")
	}
}

// a real host in a wildcard zone that resolves to a distinct address (not the
// catch-all) still survives the filter - one address outside the signature is
// enough to be a genuine record.
func TestResolve_DistinctHostSurvivesWildcard(t *testing.T) {
	const catchAll = "10.0.0.1"
	const realHost = "api." + testApex
	withFakeResolver(t, func(host string) (resolution, error) {
		if host == realHost {
			return resolution{Addrs: []string{"203.0.113.7"}}, nil
		}
		// everything else (probes + other candidates) hits the catch-all.
		return resolution{Addrs: []string{catchAll}}, nil
	})

	r := newFingerprinted(t, testApex)
	if len(r.wildcardSigs) == 0 {
		t.Fatal("wildcard zone should record at least one signature")
	}

	ok, err := r.Resolve(realHost)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !ok {
		t.Error("a host resolving to a distinct address should survive the wildcard filter")
	}
}

func TestParseResolvers(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty falls back to bundled", "", nil},
		{"blank falls back to bundled", "   ", nil},
		{"bare ips get default port", "1.1.1.1,8.8.8.8", []string{"1.1.1.1:53", "8.8.8.8:53"}},
		{"explicit port preserved", "9.9.9.9:5353", []string{"9.9.9.9:5353"}},
		{"whitespace and empties trimmed", " 1.1.1.1 , ,8.8.8.8 ", []string{"1.1.1.1:53", "8.8.8.8:53"}},
		{"mixed bare and ported", "1.1.1.1,9.9.9.9:5353", []string{"1.1.1.1:53", "9.9.9.9:5353"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseResolvers(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseResolvers(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestNewResolver_DefaultsToBundledPool(t *testing.T) {
	// keep the seam already installed so New doesn't replace it with a real
	// client; we only assert the constructor accepts an empty override.
	withFakeResolver(t, func(string) (resolution, error) { return resolution{}, nil })

	r, err := NewResolver(nil)
	if err != nil {
		t.Fatalf("NewResolver(nil): %v", err)
	}
	if r == nil {
		t.Fatal("NewResolver returned nil resolver")
	}
}
