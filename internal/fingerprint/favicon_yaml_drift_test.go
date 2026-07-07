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

// this file binds every favicon-*.yaml module to the fingerprint package's
// faviconTech table (favicon.go) so the two SSOT surfaces can't silently
// drift apart: a yaml module hardcodes a hash rather than being generated
// from the table, so nothing previously caught a yaml hash that didn't exist
// in (or disagreed with) the Go map.
package fingerprint_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vmfunc/sif/internal/fingerprint"
	"github.com/vmfunc/sif/internal/modules"
)

// modulesDir is the repo's module tree, reached the same way other
// internal/modules tests reach it (see e.g. vector_db_exposure_test.go),
// adjusted for this package's one-shallower path.
const modulesDir = "../../modules"

func findFaviconYAMLs(t *testing.T) []string {
	t.Helper()

	var found []string
	err := filepath.WalkDir(modulesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasPrefix(name, "favicon-") {
			return nil
		}
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", modulesDir, err)
	}
	if len(found) == 0 {
		t.Fatalf("no favicon-*.yaml modules found under %s; is the path stale?", modulesDir)
	}
	return found
}

// normalizeHash mirrors internal/modules' unexported normalizeFaviconHash: it
// folds a signed or unsigned 32-bit value to the signed int32 shodan stores.
func normalizeHash(t *testing.T, path string, v int64) int32 {
	t.Helper()
	if v < -(1<<31) || v > (1<<32-1) {
		t.Fatalf("%s: favicon hash %d is out of 32-bit range", path, v)
	}
	return int32(uint32(v)) //nolint:gosec // intentional 32-bit fold, mirrors modules.normalizeFaviconHash
}

// TestFaviconYAMLModulesMatchTable also checks that when a module's own name
// mentions a tech, the name agrees with what the table says the hash means.
func TestFaviconYAMLModulesMatchTable(t *testing.T) {
	for _, path := range findFaviconYAMLs(t) {
		ym, err := modules.ParseYAMLModule(path)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		if ym.HTTP == nil {
			t.Fatalf("%s: expected an http module with a favicon matcher", path)
		}

		var sawFaviconMatcher bool
		for _, m := range ym.HTTP.Matchers {
			if m.Type != "favicon" {
				continue
			}
			sawFaviconMatcher = true
			if len(m.Hash) == 0 {
				t.Errorf("%s: favicon matcher declares no hashes", path)
			}
			for _, raw := range m.Hash {
				hash := normalizeHash(t, path, raw)

				tech, ok := fingerprint.LookupFaviconTech(hash)
				if !ok {
					t.Errorf("%s: favicon hash %d is not in fingerprint.faviconTech; the yaml and the go table have drifted", path, hash)
					continue
				}

				if tech != "" && !strings.Contains(strings.ToLower(ym.Info.Name), strings.ToLower(tech)) {
					t.Errorf("%s: module name %q does not mention table tech %q for hash %d; the yaml and the go table disagree on what this hash means",
						path, ym.Info.Name, tech, hash)
				}
			}
		}
		if !sawFaviconMatcher {
			t.Errorf("%s: no favicon matcher found", path)
		}
	}
}
