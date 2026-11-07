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
	"testing/fstest"
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
		{
			// type http with no http: section at all: parses fine today and only
			// fails at Execute, which never runs on a passive scan.
			name:    "http type with no http section",
			content: "id: no-http-section\ntype: http\n",
		},
		{
			// a typo'd section name (htttp instead of http) leaves HTTP nil the
			// same way, since yaml silently ignores unknown top-level keys.
			name:    "typo'd http section",
			content: "id: typo-http-section\ntype: http\nhtttp:\n  paths: [\"/\"]\n",
		},
		{
			// a typo'd severity must fail load rather than flow into
			// Finding.Severity verbatim and never rank against a real one.
			name:    "unknown severity",
			content: "id: bad-severity\ntype: http\ninfo:\n  severity: CRTICAL\nhttp:\n  paths: [\"/\"]\n  matchers:\n    - type: status\n      status: [200]\n", //nolint:misspell // intentional typo fixture
		},
		{
			name:    "dns type with no dns section",
			content: "id: no-dns-section\ntype: dns\n",
		},
		{
			name:    "tcp type with no tcp section",
			content: "id: no-tcp-section\ntype: tcp\n",
		},
		{
			// a chained step's matchers go through the same validation as the
			// single-request ones; an unknown type there must not load.
			name:    "chained step unknown matcher type",
			content: "id: bad-step-matcher\ntype: http\nhttp:\n  requests:\n    - path: \"/\"\n      matchers:\n        - type: stauts\n          status: [200]\n",
		},
		{
			name:    "chained step uncompilable extractor",
			content: "id: bad-step-extractor\ntype: http\nhttp:\n  requests:\n    - path: \"/\"\n      extractors:\n        - type: regex\n          name: token\n          regex: [\"(unclosed\"]\n",
		},
		{
			name:    "top-level uncompilable extractor",
			content: "id: bad-http-extractor\ntype: http\nhttp:\n  paths: [\"/\"]\n  extractors:\n    - type: regex\n      name: token\n      regex: [\"(unclosed\"]\n",
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

// TestParseYAMLModuleStrictFields confirms a typo'd field inside a present
// config block (as opposed to a missing/typo'd top-level section, covered by
// TestParseYAMLModuleErrors) is rejected: strict/KnownFields decoding, not
// just the block-presence check.
func TestParseYAMLModuleStrictFields(t *testing.T) {
	dir := t.TempDir()

	typoField := writeModule(t, dir, "typo-field.yaml", "id: tf\ntype: http\nhttp:\n  methdo: GET\n  paths: [\"/\"]\n  matchers:\n    - type: status\n      status: [200]\n")
	if _, err := ParseYAMLModule(typoField); err == nil {
		t.Fatal("typo'd field (methdo) inside http section accepted")
	}

	correctField := writeModule(t, dir, "correct-field.yaml", "id: cf\ntype: http\nhttp:\n  method: GET\n  paths: [\"/\"]\n  matchers:\n    - type: status\n      status: [200]\n")
	if _, err := ParseYAMLModule(correctField); err != nil {
		t.Fatalf("valid field name rejected: %v", err)
	}
}

// TestValidateSeverity pins the known-set check: any casing of the five
// documented levels passes, an empty severity is left alone (many modules
// and test fixtures omit it; that is unrelated to catching a typo), and
// anything else, including a near-miss typo, is rejected.
func TestValidateSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		wantErr  bool
	}{
		{name: "info", severity: "info", wantErr: false},
		{name: "low", severity: "low", wantErr: false},
		{name: "medium", severity: "medium", wantErr: false},
		{name: "high", severity: "high", wantErr: false},
		{name: "critical", severity: "critical", wantErr: false},
		{name: "uppercase", severity: "HIGH", wantErr: false},
		{name: "mixed case", severity: "Medium", wantErr: false},
		{name: "empty is left alone", severity: "", wantErr: false},
		{name: "typo rejected", severity: "CRTICAL", wantErr: true}, //nolint:misspell // intentional typo fixture
		{name: "unknown word rejected", severity: "urgent", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateSeverity(tt.severity); (err != nil) != tt.wantErr {
				t.Errorf("validateSeverity(%q) err = %v, wantErr %v", tt.severity, err, tt.wantErr)
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

// TestLoaderLoadDirSkipsUnreadableEntry proves one entry the walk cannot read
// (a directory with its permissions stripped) does not abort the rest of the
// walk: a module sorted after it must still load. filepath.Walk aborts
// entirely on the first non-nil error a walkFn returns, and loadDir used to
// just pass that error straight through.
func TestLoaderLoadDirSkipsUnreadableEntry(t *testing.T) {
	Clear()
	t.Cleanup(Clear)

	if os.Getuid() == 0 {
		t.Skip("running as root: unreadable-permission trick does not apply")
	}

	dir := t.TempDir()
	unreadable := filepath.Join(dir, "a-unreadable")
	if err := os.Mkdir(unreadable, 0o755); err != nil {
		t.Fatal(err)
	}
	writeModule(t, unreadable, "inner.yaml", "id: inner-mod\ntype: http\nhttp:\n  paths: [\"/\"]\n")
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o755) })

	// "zlast" sorts after "a-unreadable" so the walk must reach it only if it
	// presses on past the unreadable directory instead of aborting there.
	writeModule(t, dir, "zlast.yaml", "id: zlast-mod\ntype: http\nhttp:\n  paths: [\"/\"]\n  matchers:\n    - type: status\n      status: [200]\n")

	l := &Loader{builtinDir: dir, userDir: filepath.Join(dir, "nonexistent-user")}
	if err := l.LoadAll(); err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	if _, ok := Get("zlast-mod"); !ok {
		t.Error("zlast-mod not registered: an unreadable entry earlier in the walk dropped it")
	}
}

// TestLoaderMergesEmbeddedAndDiskByID confirms embedded and on-disk builtins
// merge by module id, rather than the disk set winning outright whenever
// anything on disk loads: every embedded-only id must still register, and a
// disk module sharing an embedded id must override just that one entry.
func TestLoaderMergesEmbeddedAndDiskByID(t *testing.T) {
	Clear()
	t.Cleanup(Clear)

	embedded := fstest.MapFS{
		"shared.yaml": &fstest.MapFile{Data: []byte("id: shared\ntype: http\ninfo:\n  description: embedded\nhttp:\n  paths: [\"/\"]\n  matchers:\n    - type: status\n      status: [200]\n")},
		"solo-a.yaml": &fstest.MapFile{Data: []byte("id: solo-a\ntype: http\nhttp:\n  paths: [\"/\"]\n  matchers:\n    - type: status\n      status: [200]\n")},
		"solo-b.yaml": &fstest.MapFile{Data: []byte("id: solo-b\ntype: http\nhttp:\n  paths: [\"/\"]\n  matchers:\n    - type: status\n      status: [200]\n")},
	}

	dir := t.TempDir()
	writeModule(t, dir, "shared.yaml", "id: shared\ntype: http\ninfo:\n  description: disk\nhttp:\n  paths: [\"/\"]\n  matchers:\n    - type: status\n      status: [200]\n")

	l := &Loader{builtinDir: dir, userDir: filepath.Join(dir, "nonexistent-user"), embedded: embedded}
	if err := l.LoadAll(); err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	for _, id := range []string{"shared", "solo-a", "solo-b"} {
		if _, ok := Get(id); !ok {
			t.Errorf("%s not registered; embedded modules must survive a disk override elsewhere", id)
		}
	}

	shared, ok := Get("shared")
	if !ok {
		t.Fatal("shared not registered")
	}
	if got := shared.Info().Description; got != "disk" {
		t.Errorf("shared module description = %q, want %q (disk should override the embedded copy)", got, "disk")
	}
}

// TestNewLoaderPrefersTrustedBuiltinOverCWD confirms that once an embedded
// builtin set exists, NewLoader does not fall back to trusting a bare
// "modules" directory relative to the current working directory: a release
// binary run from an unrelated directory that happens to contain a modules/
// folder must not have it silently treated as a builtin source.
func TestNewLoaderPrefersTrustedBuiltinOverCWD(t *testing.T) {
	origFS := builtinFS
	t.Cleanup(func() { builtinFS = origFS })

	SetBuiltinFS(fstest.MapFS{"x.yaml": &fstest.MapFile{Data: []byte("id: x\ntype: http\nhttp:\n  paths: [\"/\"]\n")}})

	l, err := NewLoader()
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if l.BuiltinDir() == "modules" {
		t.Error("BuiltinDir() fell back to the bare CWD-relative \"modules\" path while an embedded builtin set was available")
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

func TestDataDirs(t *testing.T) {
	t.Setenv("XDG_DATA_DIRS", "/opt/a"+string(os.PathListSeparator)+"/opt/b")
	if got := dataDirs(); len(got) != 2 || got[0] != "/opt/a" || got[1] != "/opt/b" {
		t.Errorf("dataDirs() with XDG set = %v, want [/opt/a /opt/b]", got)
	}

	t.Setenv("XDG_DATA_DIRS", "")
	if got := dataDirs(); len(got) != 2 || got[0] != "/usr/local/share" || got[1] != "/usr/share" {
		t.Errorf("dataDirs() default = %v, want [/usr/local/share /usr/share]", got)
	}
}

func TestFirstExistingDir(t *testing.T) {
	tmp := t.TempDir()
	realDir := filepath.Join(tmp, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := writeModule(t, tmp, "afile", "x")

	if got := firstExistingDir([]string{filepath.Join(tmp, "missing"), file, realDir}); got != realDir {
		t.Errorf("firstExistingDir = %q, want %q (a file must be skipped)", got, realDir)
	}
	if got := firstExistingDir([]string{filepath.Join(tmp, "nope")}); got != "" {
		t.Errorf("firstExistingDir with no match = %q, want empty", got)
	}
}

// TestBuiltinDirCandidatesIncludesDataDirs is the FHS regression: packaged
// installs keep modules under <data-dir>/sif/modules, so that path must be a
// candidate, ordered after the executable-relative and working-dir paths.
func TestBuiltinDirCandidatesIncludesDataDirs(t *testing.T) {
	t.Setenv("XDG_DATA_DIRS", "/usr/share")
	candidates := builtinDirCandidates()

	want := "/usr/share/sif/modules"
	if candidates[len(candidates)-1] != want {
		t.Errorf("candidates %v missing trailing data-dir path %q", candidates, want)
	}
}

// TestResolveBuiltinDirFindsPackagedModules is the resolveBuiltinDir-level
// counterpart to TestBuiltinDirCandidatesIncludesDataDirs above.
func TestResolveBuiltinDirFindsPackagedModules(t *testing.T) {
	tmp := t.TempDir()
	pkg := filepath.Join(tmp, "sif", "modules")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_DATA_DIRS", tmp)
	t.Chdir(t.TempDir()) // scratch cwd so the "modules" candidate does not exist

	if got := resolveBuiltinDir(); got != pkg {
		t.Errorf("resolveBuiltinDir = %q, want packaged %q", got, pkg)
	}
}

// TestShippedModulesLoadClean parses every module shipped in the repo-root
// modules/ tree so a new load-time guard is checked against real modules, not
// just fixtures: it must reject genuinely bad modules without rejecting any
// of these.
func TestShippedModulesLoadClean(t *testing.T) {
	files, err := filepath.Glob("../../modules/*/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no shipped modules found; check the glob against modules/")
	}
	for _, f := range files {
		if _, err := ParseYAMLModule(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

// TestBuiltinDirCandidatesCwdTrust pins both halves of the working-directory
// rule: a sif checkout keeps the bare "modules" candidate, so editing modules/
// and re-running the binary still works, while any other directory loses it
// once an embedded set exists. Getting this wrong is silent either way - a
// dropped candidate makes on-disk edits invisible, an extra one makes a
// stranger's modules/ dir a trusted builtin source.
func TestBuiltinDirCandidatesCwdTrust(t *testing.T) {
	hasCwd := func(candidates []string) bool {
		for _, c := range candidates {
			if c == "modules" {
				return true
			}
		}
		return false
	}

	prev := builtinFS
	t.Cleanup(func() { builtinFS = prev })
	builtinFS = fstest.MapFS{}

	t.Chdir(t.TempDir())
	if hasCwd(builtinDirCandidates()) {
		t.Error("a non-checkout working directory must not offer the bare modules candidate")
	}

	checkout := t.TempDir()
	if err := os.WriteFile(filepath.Join(checkout, "go.mod"), []byte("module "+sifModulePath+"\n\ngo 1.25\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(checkout)
	if !hasCwd(builtinDirCandidates()) {
		t.Error("a sif checkout must keep the bare modules candidate so on-disk edits are seen")
	}

	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "go.mod"), []byte("module example.com/other\n\ngo 1.25\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(other)
	if hasCwd(builtinDirCandidates()) {
		t.Error("another project's checkout must not offer the bare modules candidate")
	}

	// with no embedded set there is nothing to fall back on, so cwd is offered
	// regardless of where the binary is run from.
	builtinFS = nil
	t.Chdir(t.TempDir())
	if !hasCwd(builtinDirCandidates()) {
		t.Error("without an embedded set the bare modules candidate must remain")
	}
}
