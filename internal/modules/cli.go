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
	"io"
	"os"
	"path/filepath"
	"sort"
)

// RunCommand dispatches `sif modules <sub> [args...]`. It returns a process
// exit code (0 success, 1 failures found, 2 usage error) and writes all output
// to out/errOut, so it is testable without capturing the global stdout.
func RunCommand(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, moduleUsage)
		return 2
	}
	switch args[0] {
	case "lint":
		return runLint(args[1:], out, errOut)
	case "test":
		return runTest(args[1:], out, errOut)
	case "-h", "--help", "help":
		fmt.Fprintln(out, moduleUsage)
		return 0
	default:
		fmt.Fprintf(errOut, "unknown subcommand %q\n\n%s\n", args[0], moduleUsage)
		return 2
	}
}

const moduleUsage = `usage: sif modules <command> [paths...]

commands:
  lint [paths...]   validate module yaml: schema, matchers, regex, duplicate ids
  test [paths...]   run each module's inline test: fixtures

with no paths, both commands cover the built-in and user module directories.
a path may be a module file or a directory of modules.`

// resolveTargets returns the directories/files to operate on: the given args,
// or the built-in and user module dirs when none are given.
func resolveTargets(args []string) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	loader, err := NewLoader()
	if err != nil {
		return nil, err
	}
	return []string{loader.BuiltinDir(), loader.UserDir()}, nil
}

// runLint lints the targets and prints a report. Exit 1 if any error-level
// issue is found (warnings alone keep a zero exit, so a repo can gate on lint
// without failing on style nits).
func runLint(args []string, out, errOut io.Writer) int {
	targets, err := resolveTargets(args)
	if err != nil {
		fmt.Fprintf(errOut, "lint: %v\n", err)
		return 2
	}

	report, err := LintDirs(targets)
	if err != nil {
		fmt.Fprintf(errOut, "lint: %v\n", err)
		return 2
	}

	for _, is := range report.Issues {
		w := out
		if is.Level == LintError {
			w = errOut
		}
		fmt.Fprintf(w, "%s: %s: %s\n", is.Path, is.Level, is.Msg)
	}

	fmt.Fprintf(out, "\nlinted %d module(s) across %d file(s): %d error(s), %d warning(s)\n",
		report.Modules, report.Files, report.Errors(), report.Warnings())
	if report.HasErrors() {
		return 1
	}
	return 0
}

// runTest runs inline fixtures for every module under the targets that declares
// them. Exit 1 on any failing case or load error; a module without tests is
// skipped silently when scanning a directory, but is an error when named
// explicitly as a file.
func runTest(args []string, out, errOut io.Writer) int {
	targets, err := resolveTargets(args)
	if err != nil {
		fmt.Fprintf(errOut, "test: %v\n", err)
		return 2
	}
	explicit := len(args) > 0

	files, err := collectModuleFiles(targets)
	if err != nil {
		fmt.Fprintf(errOut, "test: %v\n", err)
		return 2
	}

	var total, passed, failed, modulesRun int
	for _, path := range files {
		def, perr := ParseYAMLModule(path)
		if perr != nil {
			fmt.Fprintf(errOut, "%s: parse error: %v\n", path, perr)
			failed++
			continue
		}
		if len(def.Tests) == 0 {
			if explicit && isFileArg(args, path) {
				fmt.Fprintf(errOut, "%s: no tests defined\n", path)
				failed++
			}
			continue
		}

		results, rerr := RunModuleTests(def)
		if rerr != nil {
			fmt.Fprintf(errOut, "%s: %v\n", path, rerr)
			failed++
			continue
		}
		modulesRun++
		fmt.Fprintf(out, "%s (%s)\n", def.ID, path)
		for _, r := range results {
			total++
			if r.Passed {
				passed++
				fmt.Fprintf(out, "  ok   %s\n", r.Name)
			} else {
				failed++
				fmt.Fprintf(errOut, "  FAIL %s: %s\n", r.Name, r.Reason)
			}
		}
	}

	fmt.Fprintf(out, "\nran %d test(s) in %d module(s): %d passed, %d failed\n",
		total, modulesRun, passed, failed)
	if failed > 0 {
		return 1
	}
	return 0
}

// collectModuleFiles expands targets (files or directories) into a sorted,
// de-duplicated list of module yaml files.
func collectModuleFiles(targets []string) ([]string, error) {
	seen := make(map[string]bool)
	var files []string
	addFile := func(p string) {
		if !seen[p] {
			seen[p] = true
			files = append(files, p)
		}
	}

	for _, t := range targets {
		info, err := os.Stat(t)
		if err != nil {
			// a missing explicit path is an error; a missing default dir is not.
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if !info.IsDir() {
			addFile(t)
			continue
		}
		walkErr := filepath.Walk(t, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}
			switch filepath.Ext(path) {
			case ".yaml", ".yml":
				addFile(path)
			}
			return nil
		})
		if walkErr != nil {
			return nil, walkErr
		}
	}
	sort.Strings(files)
	return files, nil
}

// isFileArg reports whether path was named directly (not reached by walking a
// directory arg), so "no tests" is only an error for an explicitly named file.
func isFileArg(args []string, path string) bool {
	for _, a := range args {
		if a == path {
			return true
		}
	}
	return false
}
