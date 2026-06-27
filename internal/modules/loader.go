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
	"os"
	"path/filepath"
	"runtime"

	"github.com/charmbracelet/log"
	"github.com/vmfunc/sif/internal/output"
)

// Loader handles module discovery and loading.
type Loader struct {
	builtinDir string
	userDir    string
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

	builtinDir := resolveBuiltinDir()

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
	}, nil
}

// resolveBuiltinDir picks the built-in modules directory: the first existing
// candidate, or the working-directory default when none are present (LoadAll
// then logs "no built-in modules found" as before).
func resolveBuiltinDir() string {
	if dir := firstExistingDir(builtinDirCandidates()); dir != "" {
		return dir
	}
	return "modules"
}

// builtinDirCandidates lists the directories to probe for built-in modules,
// most specific first: next to the executable, the working directory (for
// development), then the freedesktop system data dirs so packaged installs
// (modules under /usr/share/sif) are found too.
func builtinDirCandidates() []string {
	candidates := make([]string, 0, 4)

	if execPath, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(execPath), "modules"))
	}
	candidates = append(candidates, "modules")

	for _, dir := range dataDirs() {
		candidates = append(candidates, filepath.Join(dir, "sif", "modules"))
	}

	return candidates
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
	// Load built-in modules first
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
