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
	"os"
	"strings"
	"testing"
)

// TestModulesDoNotPrintDirectlyToStdout guards against status/error lines that
// bypass the output sink via a raw fmt.Println(os.Stdout, ...): under
// -concurrency>1 those interleave/tear with lines the rest of the run writes
// through output.Info/Error, since only the sink is wrapped with a lock. every
// module should route its chrome through the output package instead.
func TestModulesDoNotPrintDirectlyToStdout(t *testing.T) {
	files := []string{
		"cloudstorage.go",
		"subdomaintakeover.go",
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		src := string(data)
		if strings.Contains(src, "fmt.Println(") {
			t.Errorf("%s still calls fmt.Println directly, want output.Info/Error/ScanStart instead", f)
		}
		if strings.Contains(src, "os.Stdout") {
			t.Errorf("%s references os.Stdout directly, want the output sink instead", f)
		}
	}
}
