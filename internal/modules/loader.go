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
	"runtime"

	"github.com/charmbracelet/log"
	"github.com/vmfunc/sif/internal/output"
)

// builtinFS holds the modules embedded into the binary. it's set once, from the
// repo-root package that can actually run the go:embed directive (go:embed can't
// reach a parent directory, and modules/ sits above this package). it stays nil
// in builds and tests that don't import that package, so the loader simply falls
// back to the filesystem as before.
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
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}

	// Find built-in modules relative to executable
	execPath, err := os.Executable()
	if err != nil {
		execPath = "."
	}
	builtinDir := filepath.Join(filepath.Dir(execPath), "modules")

	// Also check current working directory for development
	if _, err := os.Stat(builtinDir); os.IsNotExist(err) {
		builtinDir = "modules"
	}

	// User modules directory based on OS
	var userDir string
	switch runtime.GOOS {
	case "windows":
		userDir = filepath.Join(home, "AppData", "Local", "sif", "modules")
	default:
		userDir = filepath.Join(home, ".config", "sif", "modules")
	}

	return &Loader{
		builtinDir: builtinDir,
		userDir:    userDir,
		embedded:   builtinFS,
	}, nil
}

// LoadAll discovers and loads all modules from both built-in
// and user directories.
func (l *Loader) LoadAll() error {
	// Load built-in modules first, preferring an on-disk modules/ dir (dev tree
	// or a release that ships the folder alongside the binary).
	before := l.loaded
	if err := l.loadDir(l.builtinDir, false); err != nil {
		log.Debugf("No built-in modules found: %v", err)
	}

	// nothing on disk: fall back to the modules embedded in the binary so a bare
	// `go install`ed sif still ships its built-in modules.
	if l.loaded == before && l.embedded != nil {
		if err := l.loadFS(l.embedded); err != nil {
			log.Debugf("No embedded modules loaded: %v", err)
		}
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
