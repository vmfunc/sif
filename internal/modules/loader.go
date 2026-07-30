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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/vmfunc/sif/internal/output"
	"github.com/vmfunc/sif/internal/sifpath"
)

// builtinFS holds the modules embedded into the binary. it's set once, from the
// repo-root package that can actually run the go:embed directive (go:embed can't
// reach a parent directory, and modules/ sits above this package). it stays nil
// in builds and tests that don't import that package, so the loader simply falls
// back to the filesystem as before.
// sifModulePath is this project's go module path, used to recognise a source
// checkout as the working directory. see inSifCheckout.
const sifModulePath = "github.com/vmfunc/sif"

var builtinFS fs.FS

// SetBuiltinFS registers the embedded module filesystem. see builtinFS.
func SetBuiltinFS(fsys fs.FS) { builtinFS = fsys }

// Loader handles module discovery and loading.
type Loader struct {
	builtinDir string
	userDir    string
	embedded   fs.FS
	loaded     int
}

// NewLoader creates a new module loader.
// It automatically detects the built-in modules directory and sets up
// the user modules directory based on the operating system.
func NewLoader() (*Loader, error) {
	// resolveBuiltinDir already probes the executable dir, the working
	// directory and the system data dirs, so the per-user lookup below is the
	// only thing sifpath needs to own here.
	builtinDir := resolveBuiltinDir()

	// User modules directory (can override built-ins)
	userDir, err := sifpath.UserSubdir("modules")
	if err != nil {
		return nil, fmt.Errorf("resolve user modules dir: %w", err)
	}

	return &Loader{
		builtinDir: builtinDir,
		userDir:    userDir,
		embedded:   builtinFS,
	}, nil
}

// resolveBuiltinDir picks the built-in modules directory: the first existing
// candidate, or the working-directory default when none are present (LoadAll
// then logs "no built-in modules found" as before).
func resolveBuiltinDir() string {
	if dir := firstExistingDir(builtinDirCandidates()); dir != "" {
		return dir
	}
	if builtinFS != nil {
		// an embedded set is the baseline; do not point the disk walk at the
		// working directory just to have a path.
		return ""
	}
	return "modules"
}

// builtinDirCandidates lists the directories to probe for built-in modules,
// most specific first: next to the executable, the working directory (for
// development), then the freedesktop system data dirs so packaged installs
// (modules under /usr/share/sif) are found too.
//
// The bare "modules" candidate resolves against whatever the working directory
// happens to be at runtime, so it is only offered when the working directory is
// a sif checkout (or when the binary carries no embedded set at all). That keeps
// the development flow of editing modules/ and re-running the binary, without
// letting a release binary run from some unrelated directory treat a modules/
// folder it happens to find there as a trusted builtin source.
func builtinDirCandidates() []string {
	candidates := make([]string, 0, 4)

	if execPath, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(execPath), "modules"))
	}
	if builtinFS == nil || inSifCheckout() {
		candidates = append(candidates, "modules")
	}

	for _, dir := range dataDirs() {
		candidates = append(candidates, filepath.Join(dir, "sif", "modules"))
	}

	return candidates
}

// inSifCheckout reports whether the working directory is a sif source tree, by
// reading the module path out of its go.mod. It is what separates "the developer
// is running from the repo" from "the binary happens to be sitting next to some
// other project's modules/ dir".
func inSifCheckout() bool {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest) == sifModulePath
		}
	}
	return false
}

// dataDirs returns the freedesktop base data directories, honoring
// $XDG_DATA_DIRS and falling back to the spec default when it is unset.
func dataDirs() []string {
	if env := os.Getenv("XDG_DATA_DIRS"); env != "" {
		return filepath.SplitList(env)
	}
	return []string{"/usr/local/share", "/usr/share"}
}

func firstExistingDir(candidates []string) string {
	for _, dir := range candidates {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
	}
	return ""
}

// LoadAll discovers and loads all modules from both built-in
// and user directories.
func (l *Loader) LoadAll() error {
	// Load the modules embedded in the binary first, as the baseline builtin
	// set, then layer the on-disk builtin dir over it. loadDir and loadFS
	// both register by id, and Register replaces an existing id rather than
	// duplicating it, so a disk module overrides only its own id; every other
	// embedded module survives. This also covers the release-binary case
	// (embedded, no builtinDir on disk) and the dev-tree case (both present,
	// disk wins for whatever it ships) without an all-or-nothing choice
	// between them.
	if l.embedded != nil {
		if err := l.loadFS(l.embedded); err != nil {
			log.Debugf("No embedded modules loaded: %v", err)
		}
	}
	if err := l.loadDir(l.builtinDir, false); err != nil {
		log.Debugf("No built-in modules found: %v", err)
	}

	// Load user modules (can override built-in)
	if err := l.loadDir(l.userDir, true); err != nil {
		// User dir might not exist, that's OK
		if !os.IsNotExist(err) {
			log.Debugf("No user modules found: %v", err)
		}
	}

	if l.loaded > 0 {
		modLog := output.Module("MODULES")
		modLog.Info("Loaded %d modules", l.loaded)
	}
	return nil
}

// loadDir loads modules from a directory.
func (l *Loader) loadDir(dir string, userDefined bool) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		switch filepath.Ext(path) {
		case ".yaml", ".yml":
			if err := l.loadYAML(path); err != nil {
				log.Warnf("Failed to load module %s: %v", path, err)
			} else {
				l.loaded++
			}
		case ".go":
			if err := l.loadScript(path); err != nil {
				log.Debugf("Failed to load script %s: %v", path, err)
			} else {
				l.loaded++
			}
		}

		return nil
	})
}

// loadFS loads yaml modules from an embedded filesystem. only yaml is embedded
// (the .go script path is a filesystem-only dev affordance), so this walks for
// yaml files and parses them from bytes.
func (l *Loader) loadFS(fsys fs.FS) error {
	return fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch filepath.Ext(path) {
		case ".yaml", ".yml":
			data, rerr := fs.ReadFile(fsys, path)
			if rerr != nil {
				log.Warnf("Failed to read embedded module %s: %v", path, rerr)
				return nil
			}
			def, perr := ParseYAMLModuleBytes(data)
			if perr != nil {
				log.Warnf("Failed to load embedded module %s: %v", path, perr)
				return nil
			}
			Register(newYAMLModuleWrapper(def, path))
			l.loaded++
		}
		return nil
	})
}

// loadYAML loads a YAML module definition.
func (l *Loader) loadYAML(path string) error {
	def, err := ParseYAMLModule(path)
	if err != nil {
		return err
	}

	module := newYAMLModuleWrapper(def, path)
	Register(module)
	return nil
}

// loadScript loads a Go script module.
// Implementation will be provided in script.go.
func (l *Loader) loadScript(path string) error {
	// Will be implemented in script.go
	return nil
}

// BuiltinDir returns the built-in modules directory path.
func (l *Loader) BuiltinDir() string {
	return l.builtinDir
}

// UserDir returns the user modules directory path.
func (l *Loader) UserDir() string {
	return l.userDir
}

// Loaded returns the number of loaded modules.
func (l *Loader) Loaded() int {
	return l.loaded
}
