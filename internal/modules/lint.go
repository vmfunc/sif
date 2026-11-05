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
	"regexp"
	"sort"
	"strings"
)

// LintLevel is the severity of a lint finding.
type LintLevel string

const (
	// LintError is a problem that makes a module invalid: it won't load or can
	// never fire. A run with any error exits non-zero.
	LintError LintLevel = "error"
	// LintWarning is a smell that is allowed but discouraged (a missing author,
	// no tags). It does not fail the run on its own.
	LintWarning LintLevel = "warning"
)

// LintIssue is one problem found in one module file.
type LintIssue struct {
	Path  string
	ID    string // module id, when the file parsed far enough to have one
	Level LintLevel
	Msg   string
}

// LintReport is the result of linting a set of directories.
type LintReport struct {
	Issues  []LintIssue
	Files   int // yaml files seen
	Modules int // files that parsed into a module
}

// knownModuleTypes is the set of type: values the executor can run. A module of
// any other type loads but never does anything, so lint rejects it.
var knownModuleTypes = map[ModuleType]bool{
	TypeHTTP:        true,
	TypeDNS:         true,
	TypeTCP:         true,
	TypeFingerprint: true,
	TypeScript:      true,
}

// knownSeverities is the severity vocabulary used across the module tree and
// the notify/severity-floor logic. An unknown severity would sort and render
// unpredictably, so lint rejects it.
var knownSeverities = map[string]bool{
	"info":     true,
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

// Errors returns the number of error-level issues.
func (r *LintReport) Errors() int { return r.count(LintError) }

// Warnings returns the number of warning-level issues.
func (r *LintReport) Warnings() int { return r.count(LintWarning) }

func (r *LintReport) count(level LintLevel) int {
	n := 0
	for _, is := range r.Issues {
		if is.Level == level {
			n++
		}
	}
	return n
}

// HasErrors reports whether any error-level issue was found.
func (r *LintReport) HasErrors() bool { return r.Errors() > 0 }

// LintDirs lints every yaml module under each directory. Missing directories
// are skipped (a user with no custom modules dir is not an error). Duplicate
// IDs are detected across all files from all directories in one pass, so a user
// module shadowing a built-in is reported with both paths.
func LintDirs(dirs []string) (*LintReport, error) {
	report := &LintReport{}
	// idPaths maps a module id to every file that declares it, for dup reporting.
	idPaths := make(map[string][]string)

	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		walkErr := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}
			switch filepath.Ext(path) {
			case ".yaml", ".yml":
				report.Files++
				id := lintFile(path, report)
				if id != "" {
					report.Modules++
					idPaths[id] = append(idPaths[id], path)
				}
			}
			return nil
		})
		if walkErr != nil {
			return nil, fmt.Errorf("walk %q: %w", dir, walkErr)
		}
	}

	addDuplicateIssues(idPaths, report)
	sortIssues(report)
	return report, nil
}

// lintFile parses and checks one module file, appending any issues to report,
// and returns the module id (empty when the file could not be parsed into a
// module with an id).
func lintFile(path string, report *LintReport) string {
	add := func(level LintLevel, id, format string, a ...any) {
		report.Issues = append(report.Issues, LintIssue{Path: path, ID: id, Level: level, Msg: fmt.Sprintf(format, a...)})
	}

	data, err := os.ReadFile(path)
	if err != nil {
		add(LintError, "", "read file: %v", err)
		return ""
	}

	def, err := ParseYAMLModuleBytes(data)
	if err != nil {
		// ParseYAMLModuleBytes already validates id/type presence, matchers,
		// attack mode, tcp and fingerprint; surface its message as the error.
		add(LintError, "", "%v", err)
		return ""
	}

	id := def.ID
	if !knownModuleTypes[def.Type] {
		add(LintError, id, "unknown type %q (want http, dns, tcp, fingerprint or script)", def.Type)
	}
	lintInfo(def, id, add)
	lintHTTPPaths(def, id, add)
	lintRegexes(def, id, add)
	return id
}

// lintHTTPPaths flags an http request path that is neither absolute nor anchored
// to {{BaseURL}}: the executor substitutes {{BaseURL}} for the target, so a bare
// "/foo" path becomes a relative URL the client cannot dial, and the module can
// never fire. A path with a {{payload}}/{{word}} fuzz template is fine as long
// as it is still anchored.
func lintHTTPPaths(def *YAMLModule, id string, add func(LintLevel, string, string, ...any)) {
	if def.HTTP == nil {
		return
	}
	for _, p := range def.HTTP.Paths {
		if !pathAnchored(p) {
			add(LintError, id, "http path %q is relative: anchor it to {{BaseURL}} or use an absolute url", p)
		}
	}
	for i := range def.HTTP.Requests {
		if p := def.HTTP.Requests[i].Path; !pathAnchored(p) {
			add(LintError, id, "request %d path %q is relative: anchor it to {{BaseURL}} or use an absolute url", i, p)
		}
	}
}

// pathAnchored reports whether a module path resolves to an absolute URL after
// {{BaseURL}} substitution.
func pathAnchored(p string) bool {
	lower := strings.ToLower(p)
	return strings.Contains(lower, "{{baseurl}}") ||
		strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://")
}

// lintInfo checks the metadata block: name, severity and description are
// required; author and tags are recommended.
func lintInfo(def *YAMLModule, id string, add func(LintLevel, string, string, ...any)) {
	if def.Info.Name == "" {
		add(LintError, id, "missing required field: info.name")
	}
	switch {
	case def.Info.Severity == "":
		add(LintError, id, "missing required field: info.severity")
	case !knownSeverities[def.Info.Severity]:
		add(LintError, id, "unknown severity %q (want info, low, medium, high or critical)", def.Info.Severity)
	}
	if def.Info.Description == "" {
		add(LintError, id, "missing required field: info.description")
	}
	if def.Info.Author == "" {
		add(LintWarning, id, "missing recommended field: info.author")
	}
	if len(def.Info.Tags) == 0 {
		add(LintWarning, id, "missing recommended field: info.tags")
	}
}

// lintRegexes compiles every regex a module carries so a bad pattern is caught
// at lint time rather than silently skipped at match time (checkRegex and
// runExtractors swallow compile errors on the hot path).
func lintRegexes(def *YAMLModule, id string, add func(LintLevel, string, string, ...any)) {
	compile := func(where string, patterns []string) {
		for _, p := range patterns {
			if _, err := regexp.Compile(p); err != nil {
				add(LintError, id, "%s: invalid regex %q: %v", where, p, err)
			}
		}
	}

	var (
		matchers   []Matcher
		extractors []Extractor
	)
	switch {
	case def.HTTP != nil:
		matchers, extractors = def.HTTP.Matchers, def.HTTP.Extractors
		for i := range def.HTTP.Requests {
			step := &def.HTTP.Requests[i]
			for j := range step.Matchers {
				if step.Matchers[j].Type == "regex" {
					compile(fmt.Sprintf("request %d matcher", i), step.Matchers[j].Regex)
				}
			}
			for j := range step.Extractors {
				if step.Extractors[j].Type == "regex" {
					compile(fmt.Sprintf("request %d extractor %q", i, step.Extractors[j].Name), step.Extractors[j].Regex)
				}
			}
		}
	case def.DNS != nil:
		matchers, extractors = def.DNS.Matchers, def.DNS.Extractors
	case def.TCP != nil:
		matchers, extractors = def.TCP.Matchers, def.TCP.Extractors
	}

	for i := range matchers {
		if matchers[i].Type == "regex" {
			compile("matcher", matchers[i].Regex)
		}
	}
	for i := range extractors {
		if extractors[i].Type == "regex" {
			compile(fmt.Sprintf("extractor %q", extractors[i].Name), extractors[i].Regex)
		}
	}
}

// addDuplicateIssues reports every id claimed by more than one file. The issue
// is attached to each path involved so the output points at all offenders.
func addDuplicateIssues(idPaths map[string][]string, report *LintReport) {
	for id, paths := range idPaths {
		if len(paths) < 2 {
			continue
		}
		sort.Strings(paths)
		for _, p := range paths {
			others := make([]string, 0, len(paths)-1)
			for _, q := range paths {
				if q != p {
					others = append(others, q)
				}
			}
			report.Issues = append(report.Issues, LintIssue{
				Path:  p,
				ID:    id,
				Level: LintError,
				Msg:   fmt.Sprintf("duplicate module id %q (also declared in %v)", id, others),
			})
		}
	}
}

// sortIssues orders issues by path then level (errors before warnings) so the
// report reads top-to-bottom per file and is stable across runs.
func sortIssues(report *LintReport) {
	sort.SliceStable(report.Issues, func(i, j int) bool {
		a, b := report.Issues[i], report.Issues[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Level == LintError && b.Level == LintWarning
	})
}
