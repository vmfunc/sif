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

// Package patchnotes shows release notes pulled from the github releases.
package patchnotes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/glamour"
)

const releasesAPI = "https://api.github.com/repos/vmfunc/sif/releases"

type release struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	Body    string `json:"body"`
	URL     string `json:"html_url"`
}

func fetch(ctx context.Context, path string) (*release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesAPI+path, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github returned %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}

	var r release
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// render turns a release's markdown body into styled terminal output, falling
// back to the raw body if glamour can't render it.
func render(r *release) string {
	out, err := glamour.Render(r.Body, "dark")
	if err != nil {
		return r.Body
	}
	return fmt.Sprintf("%s\n%s", r.TagName, out)
}

// Print fetches the latest release and writes its notes to stdout. tag may be
// empty for the latest release, or a "vX" tag for a specific one.
func Print(tag string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	path := "/latest"
	if tag != "" {
		path = "/tags/" + tag
	}

	r, err := fetch(ctx, path)
	if err != nil {
		fmt.Printf("couldn't fetch patch notes: %v\n", err)
		return
	}
	fmt.Print(render(r))
}

// ShowOnce prints the running version's notes the first time that version runs,
// then records it so it isn't shown again. best-effort: dev builds, the
// SIF_NO_PATCHNOTES opt-out, and any network failure stay silent.
func ShowOnce(version string) {
	if version == "" || version == "dev" || os.Getenv("SIF_NO_PATCHNOTES") != "" {
		return
	}

	path, err := statePath()
	if err != nil || hasSeen(path, version) {
		return
	}
	// record before fetching so a flaky network doesn't nag on every run
	recordSeen(path, version)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	r, err := fetch(ctx, "/tags/v"+version)
	if err != nil {
		return
	}
	fmt.Printf("\nwhat's new in this release:\n%s", render(r))
}

func statePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sif", "seen_version"), nil
}

func hasSeen(path, version string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == version
}

func recordSeen(path, version string) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return
	}
	_ = os.WriteFile(path, []byte(version), 0o600)
}
