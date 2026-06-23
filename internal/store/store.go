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

// Package store persists a run's normalized findings as a json snapshot, one
// file per target, so a later run can diff against it and surface only what
// changed. it leans on encoding/json + os only - no new deps - and keys the
// delta off finding.Key, the identity the finding layer already guarantees is
// stable across runs.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vmfunc/sif/internal/finding"
)

// snapshotFileMode is applied to written snapshot files: owner read/write only.
// a snapshot enumerates a target's findings (urls, secrets, takeovers) and is
// not meant for other users on the box, so it stays 0600.
const snapshotFileMode = 0o600

// stateDirMode is applied to directories the store creates: owner rwx, group rx,
// no world access. matches the 0o750 the bundle asks for so the state tree isn't
// world-readable.
const stateDirMode = 0o750

// snapshotExt is the extension every snapshot file carries; makes the state dir
// self-describing and lets Load reconstruct the path from a bare target.
const snapshotExt = ".json"

// defaultDirName is the sif-owned subdirectory under the user's config dir when
// no explicit store dir is given. DefaultDir joins it under os.UserConfigDir().
const defaultDirName = "sif"

// stateSubDir separates snapshots from anything else sif might drop in its
// config dir later, so the state tree is a single sweepable directory.
const stateSubDir = "state"

// DefaultDir returns the fallback snapshot location: <user-config>/sif/state.
// callers pass it when -store is unset and there's no logdir to reuse. the dir
// is not created here - Save does that lazily so a diff-less run touches nothing.
func DefaultDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolving user config dir: %w", err)
	}
	return filepath.Join(configDir, defaultDirName, stateSubDir), nil
}

// sanitize turns an arbitrary target (https://example.com:8443/path?q=1) into a
// single safe filename component. a target is attacker-influenced (it can come
// from a stdin pipe or a -f file), so every separator and path metacharacter is
// folded to '_' - no '/', '\\', '.', ':' survives to escape the state dir or
// collide with a parent reference. empty/degenerate input falls back to a fixed
// token rather than producing a dotfile or empty name.
func sanitize(target string) string {
	var b strings.Builder
	b.Grow(len(target))
	// collapse runs of separators: a scheme like "https://" is three metachars
	// in a row, and one '_' reads cleaner than three without losing uniqueness.
	prevSep := false
	for i := 0; i < len(target); i++ {
		c := target[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			b.WriteByte(c)
			prevSep = false
		default:
			// every other byte (path sep, dot, colon, slash, space, unicode, and a
			// literal '_') is a separator; fold it so traversal and dotfiles are
			// impossible and a run never balloons the filename.
			if !prevSep {
				b.WriteByte('_')
				prevSep = true
			}
		}
	}
	name := strings.Trim(b.String(), "_")
	if name == "" {
		return "target"
	}
	return name
}

// pathFor builds the absolute snapshot path for a target under dir. kept private
// so the sanitized-filename invariant lives in one place; Save and Load both go
// through it so a target always maps to the same file.
func pathFor(dir, target string) string {
	return filepath.Join(dir, sanitize(target)+snapshotExt)
}

// Save writes the run's findings for target as a json snapshot under dir,
// overwriting any prior snapshot. the dir (and parents) is created lazily with
// stateDirMode. an empty findings slice is still written - it records "this
// target had nothing", which a later diff reads as a clean baseline rather than
// a missing one.
func Save(dir, target string, findings []finding.Finding) error {
	if dir == "" {
		return fmt.Errorf("store: empty snapshot dir")
	}
	if err := os.MkdirAll(dir, stateDirMode); err != nil {
		return fmt.Errorf("creating state dir %q: %w", dir, err)
	}

	// marshal a non-nil slice so an empty run serializes to [] not null; keeps
	// the on-disk shape stable and Load's decode unambiguous.
	if findings == nil {
		findings = []finding.Finding{}
	}
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling snapshot for %q: %w", target, err)
	}

	path := pathFor(dir, target)
	if err := os.WriteFile(path, data, snapshotFileMode); err != nil {
		return fmt.Errorf("writing snapshot %q: %w", path, err)
	}
	return nil
}

// Load reads the previously saved snapshot for target under dir. a missing
// snapshot is not an error - it's the first run for that target, so an empty
// slice comes back and the caller treats every current finding as new. a present
// but unreadable/corrupt file is a real error: silently swallowing it would make
// a broken store look like a fresh one and flag everything as added forever.
func Load(dir, target string) ([]finding.Finding, error) {
	path := pathFor(dir, target)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []finding.Finding{}, nil
		}
		return nil, fmt.Errorf("reading snapshot %q: %w", path, err)
	}

	var findings []finding.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("decoding snapshot %q: %w", path, err)
	}
	if findings == nil {
		findings = []finding.Finding{}
	}
	return findings, nil
}

// Diff computes the set-difference between two snapshots keyed on Finding.Key:
// added is everything in next whose Key isn't in old, removed is everything in
// old whose Key isn't in next. order follows the input slices (added in next's
// order, removed in old's) so output is deterministic for a given pair. a Key
// seen twice in one slice is deduped on first sight, so duplicate findings don't
// double-report.
func Diff(old, next []finding.Finding) (added, removed []finding.Finding) {
	oldKeys := make(map[string]struct{}, len(old))
	for i := 0; i < len(old); i++ {
		oldKeys[old[i].Key] = struct{}{}
	}
	nextKeys := make(map[string]struct{}, len(next))
	for i := 0; i < len(next); i++ {
		nextKeys[next[i].Key] = struct{}{}
	}

	seen := make(map[string]struct{}, len(next))
	for i := 0; i < len(next); i++ {
		k := next[i].Key
		if _, ok := oldKeys[k]; ok {
			continue
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		added = append(added, next[i])
	}

	// reuse seen for the removed pass; the two key spaces don't overlap by
	// construction (removed keys are absent from next) so a single map is safe.
	clear(seen)
	for i := 0; i < len(old); i++ {
		k := old[i].Key
		if _, ok := nextKeys[k]; ok {
			continue
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		removed = append(removed, old[i])
	}
	return added, removed
}
