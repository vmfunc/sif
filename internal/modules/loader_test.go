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

package modules

import (
	"os"
	"path/filepath"
	"testing"
)

// writeModule drops a yaml file into a temp dir and returns its path.
func writeModule(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write module: %v", err)
	}
	return path
}

func TestParseYAMLModuleValid(t *testing.T) {
	const doc = `id: example-http
type: http
info:
  name: Example
  author: azzie
  severity: medium
  description: a test module
  tags: [test, demo]
http:
  method: GET
  paths:
    - "{{BaseURL}}/admin"
  matchers:
    - type: status
      status: [200]
    - type: word
      part: body
      words: ["admin"]
      condition: and
  extractors:
    - type: regex
      name: token
      part: body
      regex: ["token=(\\w+)"]
      group: 1
`
	dir := t.TempDir()
	path := writeModule(t, dir, "ok.yaml", doc)

	def, err := ParseYAMLModule(path)
	if err != nil {
		t.Fatalf("ParseYAMLModule: %v", err)
	}
	if def.ID != "example-http" {
		t.Errorf("id = %q, want example-http", def.ID)
	}
	if def.Type != TypeHTTP {
		t.Errorf("type = %q, want http", def.Type)
	}
	if def.Info.Severity != "medium" {
		t.Errorf("severity = %q, want medium", def.Info.Severity)
	}
	if def.HTTP == nil {
		t.Fatal("http config not parsed")
	}
	if len(def.HTTP.Matchers) != 2 {
		t.Errorf("got %d matchers, want 2", len(def.HTTP.Matchers))
	}
	if len(def.HTTP.Extractors) != 1 || def.HTTP.Extractors[0].Group != 1 {
		t.Errorf("extractor not parsed correctly: %+v", def.HTTP.Extractors)
	}
	if len(def.Info.Tags) != 2 {
		t.Errorf("got %d tags, want 2", len(def.Info.Tags))
	}
}

func TestParseYAMLModuleErrors(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "missing id",
			content: "type: http\nhttp:\n  paths: [\"/\"]\n",
		},
		{
			name:    "missing type",
			content: "id: no-type\nhttp:\n  paths: [\"/\"]\n",
		},
		{
			name:    "malformed yaml",
			content: "id: bad\ntype: http\n  paths: [unbalanced\n   : nope\n",
		},
		{
			// a scalar where a mapping is expected must fail to unmarshal.
			name:    "type mismatch",
			content: "id: bad-shape\ntype: http\nhttp: \"should-be-a-map\"\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeModule(t, dir, tt.name+".yaml", tt.content)
			if _, err := ParseYAMLModule(path); err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
		})
	}
}

func TestParseYAMLModuleMissingFile(t *testing.T) {
	if _, err := ParseYAMLModule(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestYAMLModuleWrapperInfoAndType(t *testing.T) {
	def := &YAMLModule{
		ID:   "wrap-test",
		Type: TypeHTTP,
		Info: YAMLModuleInfo{
			Name:        "Wrapped",
			Author:      "azzie",
			Severity:    "low",
			Description: "desc",
			Tags:        []string{"a", "b"},
		},
	}
	w := newYAMLModuleWrapper(def, "wrap.yaml")

	if w.Type() != TypeHTTP {
		t.Errorf("Type() = %q, want http", w.Type())
	}
	info := w.Info()
	if info.ID != "wrap-test" || info.Name != "Wrapped" || info.Severity != "low" {
		t.Errorf("Info() mismatch: %+v", info)
	}
	if len(info.Tags) != 2 {
		t.Errorf("Info().Tags = %v, want 2 entries", info.Tags)
	}
}

// TestLoaderLoadAll exercises the directory walk: a valid module registers, a
// malformed one is skipped without aborting the walk.
func TestLoaderLoadAll(t *testing.T) {
	Clear()
	t.Cleanup(Clear)

	dir := t.TempDir()
	writeModule(t, dir, "good.yaml", "id: good-mod\ntype: http\nhttp:\n  paths: [\"{{BaseURL}}/\"]\n  matchers:\n    - type: status\n      status: [200]\n")
	writeModule(t, dir, "bad.yml", "id: bad-mod\n") // missing type -> skipped
	writeModule(t, dir, "ignore.txt", "not a module")

	l := &Loader{builtinDir: dir, userDir: filepath.Join(dir, "nonexistent-user")}
	if err := l.LoadAll(); err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	// only the good module loads; the malformed one is logged and skipped.
	if l.Loaded() != 1 {
		t.Errorf("Loaded() = %d, want 1", l.Loaded())
	}
	if _, ok := Get("good-mod"); !ok {
		t.Error("good-mod not registered")
	}
	if _, ok := Get("bad-mod"); ok {
		t.Error("bad-mod should not have registered")
	}
}

func TestNewLoaderDirs(t *testing.T) {
	l, err := NewLoader()
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if l.BuiltinDir() == "" {
		t.Error("BuiltinDir is empty")
	}
	if l.UserDir() == "" {
		t.Error("UserDir is empty")
	}
}

// TestRegistry exercises the package-level registry: register, get, dedupe by
// id, filter by tag and type, count and clear.
func TestRegistry(t *testing.T) {
	Clear()
	t.Cleanup(Clear)

	http1 := newYAMLModuleWrapper(&YAMLModule{ID: "h1", Type: TypeHTTP, Info: YAMLModuleInfo{Tags: []string{"web", "cve"}}}, "h1")
	http2 := newYAMLModuleWrapper(&YAMLModule{ID: "h2", Type: TypeHTTP, Info: YAMLModuleInfo{Tags: []string{"web"}}}, "h2")
	dns1 := newYAMLModuleWrapper(&YAMLModule{ID: "d1", Type: TypeDNS, Info: YAMLModuleInfo{Tags: []string{"dns"}}}, "d1")

	Register(http1)
	Register(http2)
	Register(dns1)

	if Count() != 3 {
		t.Fatalf("Count() = %d, want 3", Count())
	}

	got, ok := Get("h1")
	if !ok || got.Info().ID != "h1" {
		t.Errorf("Get(h1) = %v, %v", got, ok)
	}
	if _, ok := Get("missing"); ok {
		t.Error("Get(missing) should report not found")
	}

	if n := len(ByType(TypeHTTP)); n != 2 {
		t.Errorf("ByType(http) = %d, want 2", n)
	}
	if n := len(ByType(TypeDNS)); n != 1 {
		t.Errorf("ByType(dns) = %d, want 1", n)
	}
	if n := len(ByTag("web")); n != 2 {
		t.Errorf("ByTag(web) = %d, want 2", n)
	}
	if n := len(ByTag("cve")); n != 1 {
		t.Errorf("ByTag(cve) = %d, want 1", n)
	}
	if n := len(ByTag("none")); n != 0 {
		t.Errorf("ByTag(none) = %d, want 0", n)
	}
	if n := len(All()); n != 3 {
		t.Errorf("All() = %d, want 3", n)
	}

	// re-registering the same id overwrites rather than duplicating.
	Register(newYAMLModuleWrapper(&YAMLModule{ID: "h1", Type: TypeHTTP}, "h1-v2"))
	if Count() != 3 {
		t.Errorf("Count() after re-register = %d, want 3", Count())
	}

	Clear()
	if Count() != 0 {
		t.Errorf("Count() after Clear = %d, want 0", Count())
	}
}

// TestResultType pins the ScanResult interface bridge.
func TestResultType(t *testing.T) {
	r := &Result{ModuleID: "abc"}
	if r.ResultType() != "abc" {
		t.Errorf("ResultType() = %q, want abc", r.ResultType())
	}
}

// TestLoaderScriptStubNoop confirms the go-script loader is currently a no-op
// that registers nothing and returns no error.
func TestLoaderScriptStubNoop(t *testing.T) {
	l := &Loader{}
	if err := l.loadScript("anything.go"); err != nil {
		t.Errorf("loadScript stub returned error: %v", err)
	}
}
