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
	"path/filepath"
	"strings"
	"testing"

	"github.com/vmfunc/sif/internal/modules"
)

// favicon demo modules must reference a hash from faviconHashes that names the
// service in their filename, so a demo cannot drift from the scanner's map.
func TestFaviconDemoModulesMatchCanonicalMap(t *testing.T) {
	matches, err := filepath.Glob("../../modules/info/favicon-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Skip("no favicon demo modules present")
	}

	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			def, err := modules.ParseYAMLModule(path)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if def.HTTP == nil {
				t.Fatal("favicon demo is not an http module")
			}

			var hashes []int64
			for _, m := range def.HTTP.Matchers {
				if m.Type == "favicon" {
					hashes = append(hashes, m.Hash...)
				}
			}
			if len(hashes) == 0 {
				t.Fatal("no favicon hash in module")
			}

			service := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "favicon-"), ".yaml")
			for _, h := range hashes {
				// hashes are range-checked at parse, so int32(h) is the canonical fold.
				tech, ok := faviconHashes[int32(h)]
				if !ok {
					t.Errorf("hash %d is absent from faviconHashes; demo references a hash the scanner does not know", h)
					continue
				}
				if !strings.Contains(strings.ToLower(tech), service) {
					t.Errorf("hash %d maps to %q, but the file names service %q", h, tech, service)
				}
			}
		})
	}
}
