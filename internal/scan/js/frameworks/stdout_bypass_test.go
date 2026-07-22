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

package frameworks

import (
	"os"
	"strings"
	"testing"
)

// TestNextDoesNotPrintDirectlyToStdout mirrors internal/scan's guard: next.go
// used to fmt.Println(err) straight to os.Stdout, which can interleave/tear
// under -concurrency>1 since only the output sink is lock-wrapped there.
func TestNextDoesNotPrintDirectlyToStdout(t *testing.T) {
	data, err := os.ReadFile("next.go")
	if err != nil {
		t.Fatalf("reading next.go: %v", err)
	}
	src := string(data)
	if strings.Contains(src, "fmt.Println(") {
		t.Error("next.go still calls fmt.Println directly, want output.Error instead")
	}
	if strings.Contains(src, "os.Stdout") {
		t.Error("next.go references os.Stdout directly, want the output sink instead")
	}
}
