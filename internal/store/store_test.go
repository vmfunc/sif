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

package store

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/vmfunc/sif/internal/finding"
)

// sampleFindings is a small, stable set of findings reused across the round-trip
// and diff cases; covers two modules and two severities so marshaling exercises
// every Finding field.
func sampleFindings() []finding.Finding {
	return []finding.Finding{
		{
			Target:   "https://example.com",
			Module:   "headers",
			Severity: finding.SeverityInfo,
			Key:      "headers:Server",
			Title:    "Server",
			Raw:      "nginx",
		},
		{
			Target:   "https://example.com",
			Module:   "cors",
			Severity: finding.SeverityMedium,
			Key:      "cors:https://example.com:null",
			Title:    "null origin reflected",
			Raw:      "allow-origin: null",
		},
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	const target = "https://example.com"
	want := sampleFindings()

	if err := Save(dir, target, want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := Load(dir, target)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch:\n got=%#v\nwant=%#v", got, want)
	}
}

func TestSaveCreatesNestedDir(t *testing.T) {
	// the state dir need not exist; Save mkdir's it (and parents) lazily.
	dir := filepath.Join(t.TempDir(), "nested", "state")
	if err := Save(dir, "https://x.test", sampleFindings()); err != nil {
		t.Fatalf("Save into missing dir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat created dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("expected %q to be a directory", dir)
	}
}

func TestSaveEmptyDirRejected(t *testing.T) {
	if err := Save("", "https://x.test", sampleFindings()); err == nil {
		t.Fatal("Save with empty dir: want error, got nil")
	}
}

func TestSaveEmptyFindingsRoundTrips(t *testing.T) {
	// an empty run is a valid baseline: Save writes [], Load reads back an empty
	// (non-nil) slice, never an error.
	dir := t.TempDir()
	const target = "https://empty.test"

	if err := Save(dir, target, nil); err != nil {
		t.Fatalf("Save nil findings: %v", err)
	}
	got, err := Load(dir, target)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil {
		t.Fatal("Load returned nil, want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("Load returned %d findings, want 0", len(got))
	}
}

func TestLoadMissingSnapshotIsEmpty(t *testing.T) {
	// no prior run for this target: a missing file is not an error, it's an empty
	// baseline so the first run treats everything as added.
	dir := t.TempDir()
	got, err := Load(dir, "https://never-scanned.test")
	if err != nil {
		t.Fatalf("Load missing snapshot: %v", err)
	}
	if got == nil {
		t.Fatal("Load returned nil, want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("Load missing snapshot returned %d findings, want 0", len(got))
	}
}

func TestLoadCorruptSnapshotErrors(t *testing.T) {
	// a present-but-garbage snapshot must surface loudly: treating it as empty
	// would silently re-flag every finding as new on every run.
	dir := t.TempDir()
	const target = "https://corrupt.test"
	path := filepath.Join(dir, sanitize(target)+snapshotExt)
	if err := os.WriteFile(path, []byte("{not json"), snapshotFileMode); err != nil {
		t.Fatalf("seeding corrupt snapshot: %v", err)
	}
	if _, err := Load(dir, target); err == nil {
		t.Fatal("Load corrupt snapshot: want error, got nil")
	}
}

func TestDiffAddedAndRemoved(t *testing.T) {
	base := sampleFindings()

	// next drops the cors finding (removed) and adds a takeover (added); the
	// headers finding is unchanged and must appear in neither delta.
	next := []finding.Finding{
		base[0], // headers - unchanged
		{
			Target:   "https://example.com",
			Module:   "subdomain_takeover",
			Severity: finding.SeverityHigh,
			Key:      "subdomain_takeover:old.example.com",
			Title:    "takeover: old.example.com",
			Raw:      "GitHub Pages",
		},
	}

	added, removed := Diff(base, next)

	if len(added) != 1 || added[0].Key != "subdomain_takeover:old.example.com" {
		t.Fatalf("added = %#v, want the takeover only", added)
	}
	if len(removed) != 1 || removed[0].Key != "cors:https://example.com:null" {
		t.Fatalf("removed = %#v, want the cors finding only", removed)
	}
}

func TestDiffNoChange(t *testing.T) {
	// identical snapshots produce no delta in either direction.
	base := sampleFindings()
	added, removed := Diff(base, base)
	if len(added) != 0 || len(removed) != 0 {
		t.Fatalf("identical snapshots: added=%d removed=%d, want 0/0", len(added), len(removed))
	}
}

func TestDiffFirstRunAllAdded(t *testing.T) {
	// no prior snapshot (empty old) means every current finding is new.
	next := sampleFindings()
	added, removed := Diff(nil, next)
	if len(removed) != 0 {
		t.Fatalf("first run removed=%d, want 0", len(removed))
	}
	gotKeys := keysOf(added)
	wantKeys := keysOf(next)
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Fatalf("first run added keys=%v, want %v", gotKeys, wantKeys)
	}
}

func TestDiffDedupesRepeatedKey(t *testing.T) {
	// a Key appearing twice in the new snapshot is reported once, not twice.
	f := sampleFindings()[0]
	next := []finding.Finding{f, f}
	added, _ := Diff(nil, next)
	if len(added) != 1 {
		t.Fatalf("duplicate key reported %d times, want 1", len(added))
	}
}

// keysOf returns the sorted Key set of a finding slice for order-independent
// comparison.
func keysOf(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for i := 0; i < len(fs); i++ {
		out = append(out, fs[i].Key)
	}
	sort.Strings(out)
	return out
}

func TestSanitizeNoTraversal(t *testing.T) {
	// sanitize is the only barrier between an attacker-influenced target and the
	// state dir; assert no separator or traversal token survives.
	tests := []struct {
		in   string
		want string
	}{
		{"https://example.com", "https_example_com"},
		{"../../etc/passwd", "etc_passwd"},
		{"a/b/c", "a_b_c"},
		{"....//....//x", "x"},
		{"", "target"},
		{"///", "target"},
		{"host:8443/path?q=1", "host_8443_path_q_1"},
	}
	for _, tt := range tests {
		got := sanitize(tt.in)
		if got != tt.want {
			t.Errorf("sanitize(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if filepath.Base(got) != got {
			t.Errorf("sanitize(%q) = %q escapes its component", tt.in, got)
		}
	}
}
