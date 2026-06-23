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

package scan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	charmlog "github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/httpx"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/output"
	"github.com/dropalldatabases/sif/internal/pool"
)

// directoryURL is a var so integration tests can repoint it at a fixture.
var directoryURL = "https://raw.githubusercontent.com/dropalldatabases/sif-runtime/main/dirlist/"

const (
	smallFile  = "directory-list-2.3-small.txt"
	mediumFile = "directory-list-2.3-medium.txt"
	bigFile    = "directory-list-2.3-big.txt"
)

// dirlistBodyCap bounds how many bytes we read per response before computing
// size/word counts. modern apps stream large html; capping keeps memory flat
// and makes size/word matching deterministic against arbitrarily large bodies.
const dirlistBodyCap = 512 * 1024

// soft-404 calibration probes. we ask for a handful of deterministic paths that
// cannot exist, then treat any response shape they share as the wildcard
// baseline. deterministic (no rng) so the workflow stays reproducible.
const (
	calibrationProbes = 3
	calibrationPrefix = "/sif-cal-"
)

// statusNotFound / statusForbidden are the historical default "not interesting"
// codes; they seed the filter set when no explicit -mc/-fc is given.
const (
	statusNotFound  = 404
	statusForbidden = 403
)

type DirectoryResult struct {
	Url        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Size       int    `json:"size"`
	Words      int    `json:"words"`
}

// DirlistOptions carries the ffuf-style matcher knobs. the zero value reproduces
// the legacy behavior (report everything that isn't 404/403), so callers that
// don't set anything keep the old defaults.
type DirlistOptions struct {
	MatchCodes  string // -mc comma list of status codes to keep
	FilterCodes string // -fc comma list of status codes to drop
	FilterSizes string // -fs comma list of body sizes to drop
	FilterWords string // -fw comma list of word counts to drop
	FilterRegex string // -fr regex; a body match drops the response
	Calibrate   bool   // -ac auto-calibrate the soft-404 wildcard baseline
	Wordlist    string // -w local path or url; overrides the size switch
	Extensions  string // -e comma list appended to each word (php,bak,env)
}

// responseMeta is the shape we match on: just enough of the response to decide
// keep/drop without holding the whole body.
type responseMeta struct {
	status int
	size   int
	words  int
}

// matcher decides whether a response is "interesting" using the same precedence
// as ffuf/feroxbuster: an explicit filter (-fc/-fs/-fw/-fr or a calibrated
// baseline) drops the response, otherwise the match-code set decides.
type matcher struct {
	matchCodes  map[int]struct{}
	filterCodes map[int]struct{}
	filterSizes map[int]struct{}
	filterWords map[int]struct{}
	filterRe    *regexp.Regexp
	baselines   []responseMeta // calibrated soft-404 shapes to suppress
}

// newMatcher builds the matcher from raw flag strings. when -mc is empty the
// match set is left nil, which Matches reads as "keep anything not explicitly
// filtered" - i.e. the legacy behavior minus the hardcoded 404/403, which move
// into the filter set instead.
func newMatcher(opts *DirlistOptions) (*matcher, error) {
	m := &matcher{
		filterSizes: make(map[int]struct{}),
		filterWords: make(map[int]struct{}),
	}

	codes, err := parseIntSet(opts.MatchCodes)
	if err != nil {
		return nil, fmt.Errorf("parse -mc: %w", err)
	}
	m.matchCodes = codes

	m.filterCodes, err = parseIntSet(opts.FilterCodes)
	if err != nil {
		return nil, fmt.Errorf("parse -fc: %w", err)
	}
	// no explicit match set means we fall back to the historical "drop 404/403"
	// behavior; encode it as filters so the rest of the logic is uniform.
	if len(m.matchCodes) == 0 && len(m.filterCodes) == 0 {
		m.filterCodes[statusNotFound] = struct{}{}
		m.filterCodes[statusForbidden] = struct{}{}
	}

	m.filterSizes, err = parseIntSet(opts.FilterSizes)
	if err != nil {
		return nil, fmt.Errorf("parse -fs: %w", err)
	}

	m.filterWords, err = parseIntSet(opts.FilterWords)
	if err != nil {
		return nil, fmt.Errorf("parse -fw: %w", err)
	}

	if opts.FilterRegex != "" {
		re, err := regexp.Compile(opts.FilterRegex)
		if err != nil {
			return nil, fmt.Errorf("parse -fr: %w", err)
		}
		m.filterRe = re
	}

	return m, nil
}

// Matches reports whether the response should surface as a finding. filters win
// over matches: a calibrated baseline, an -fc/-fs/-fw hit, or an -fr body match
// always drops the response; otherwise the -mc set (when set) gates it.
func (m *matcher) Matches(meta responseMeta, body []byte) bool {
	// a calibrated soft-404 shape is the same response the catch-all hands every
	// bogus path, so drop anything that matches a baseline exactly.
	for i := 0; i < len(m.baselines); i++ {
		b := m.baselines[i]
		if b.status == meta.status && b.size == meta.size && b.words == meta.words {
			return false
		}
	}

	if _, drop := m.filterCodes[meta.status]; drop {
		return false
	}
	if _, drop := m.filterSizes[meta.size]; drop {
		return false
	}
	if _, drop := m.filterWords[meta.words]; drop {
		return false
	}
	if m.filterRe != nil && m.filterRe.Match(body) {
		return false
	}

	// an explicit -mc set is allow-list semantics; without it we keep whatever
	// survived the filters above.
	if len(m.matchCodes) > 0 {
		_, keep := m.matchCodes[meta.status]
		return keep
	}

	return true
}

// parseIntSet turns a comma list like "200,301,500" into a set. empty input is a
// nil set, not an error, so unset flags are a no-op.
func parseIntSet(raw string) (map[int]struct{}, error) {
	set := make(map[int]struct{})
	if raw == "" {
		return set, nil
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid integer %q: %w", part, err)
		}
		set[n] = struct{}{}
	}
	return set, nil
}

// readMeta drains the response (capped) and returns its match shape plus the
// body bytes the regex filter needs. it never returns the raw resp; callers
// close the body before this returns.
func readMeta(resp *http.Response) (responseMeta, []byte) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, dirlistBodyCap))
	if err != nil {
		// a truncated/aborted body still has a usable status; treat what we read
		// as the body rather than dropping the whole response.
		charmlog.Debugf("dirlist: read body: %v", err)
	}
	return responseMeta{
		status: resp.StatusCode,
		size:   len(body),
		words:  countWords(body),
	}, body
}

// countWords counts whitespace-separated tokens; the cheap proxy ffuf uses to
// tell a soft-404 stub apart from a real page of the same byte size.
func countWords(body []byte) int {
	return len(strings.Fields(string(body)))
}

// expandWords appends each extension to every base word, keeping the bare word
// too. an empty extensions list returns the words unchanged.
func expandWords(words []string, extensions string) []string {
	exts := splitExtensions(extensions)
	if len(exts) == 0 {
		return words
	}
	// each word yields itself plus one entry per extension.
	expanded := make([]string, 0, len(words)*(len(exts)+1))
	for i := 0; i < len(words); i++ {
		expanded = append(expanded, words[i])
		for j := 0; j < len(exts); j++ {
			expanded = append(expanded, words[i]+"."+exts[j])
		}
	}
	return expanded
}

// splitExtensions normalizes "php, .bak ,env" into ["php","bak","env"]; a
// leading dot is tolerated so both "php" and ".php" work.
func splitExtensions(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	exts := make([]string, 0, len(parts))
	for i := 0; i < len(parts); i++ {
		ext := strings.TrimSpace(parts[i])
		ext = strings.TrimPrefix(ext, ".")
		if ext != "" {
			exts = append(exts, ext)
		}
	}
	return exts
}

// loadWordlist reads the fuzzing words. a custom -w overrides the size switch:
// an http(s) value is fetched through the shared client, anything else is a
// local file. with no -w it downloads the size-selected sif-runtime list.
func loadWordlist(opts *DirlistOptions, size string, client *http.Client) ([]string, error) {
	if opts.Wordlist != "" {
		if strings.HasPrefix(opts.Wordlist, "http://") || strings.HasPrefix(opts.Wordlist, "https://") {
			return fetchWordlist(opts.Wordlist, client)
		}
		return readWordlistFile(opts.Wordlist)
	}

	var file string
	switch size {
	case "small":
		file = smallFile
	case "medium":
		file = mediumFile
	case "large":
		file = bigFile
	default:
		return nil, fmt.Errorf("unknown dirlist size %q", size)
	}
	return fetchWordlist(directoryURL+file, client)
}

// fetchWordlist downloads a remote wordlist through the shared client so proxy
// and rate-limit settings apply to the fetch too.
func fetchWordlist(listURL string, client *http.Client) ([]string, error) {
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, listURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build wordlist request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download wordlist %q: %w", listURL, err)
	}
	defer resp.Body.Close()
	lines, err := scanLines(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("download wordlist %q: %w", listURL, err)
	}
	return lines, nil
}

// readWordlistFile loads a local wordlist file.
func readWordlistFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open wordlist %q: %w", path, err)
	}
	defer f.Close()
	lines, err := scanLines(f)
	if err != nil {
		return nil, fmt.Errorf("read wordlist %q: %w", path, err)
	}
	return lines, nil
}

// scanLines reads non-empty lines into a slice.
func scanLines(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
		}
	}
	// a line past bufio's 64k cap halts the scan; surface it instead of
	// silently dropping that line and everything after it.
	return lines, scanner.Err()
}

// calibrate probes a few paths that cannot exist and records the response shapes
// the catch-all hands them. those baselines feed the matcher so a soft-404 200
// (the SPA wildcard) is suppressed before the real run. deterministic by design:
// the probe paths come from the loop index, never a random source.
func calibrate(m *matcher, baseURL string, client *http.Client) {
	for i := 0; i < calibrationProbes; i++ {
		probe := baseURL + calibrationPrefix + strconv.Itoa(i)
		req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, probe, http.NoBody)
		if err != nil {
			charmlog.Debugf("dirlist: build calibration request: %v", err)
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			charmlog.Debugf("dirlist: calibration probe %s: %v", probe, err)
			continue
		}
		meta, _ := readMeta(resp)
		resp.Body.Close()

		// a genuine hard 404 already gets filtered by code; only soft responses
		// (a 200/30x catch-all) need a size/word baseline to suppress them.
		if meta.status == statusNotFound {
			continue
		}
		if !containsBaseline(m.baselines, meta) {
			m.baselines = append(m.baselines, meta)
		}
	}
}

// containsBaseline reports whether the shape is already recorded, so repeated
// probes returning the same soft-404 don't bloat the baseline set.
func containsBaseline(baselines []responseMeta, meta responseMeta) bool {
	for i := 0; i < len(baselines); i++ {
		if baselines[i] == meta {
			return true
		}
	}
	return false
}

// Dirlist performs directory fuzzing on the target URL with ffuf-style response
// filtering, soft-404 calibration and custom wordlists.
//
//nolint:gocritic // opts is the scanner's stable public config; passed by value to match the other scanners' entry points.
func Dirlist(size string, url string, timeout time.Duration, threads int, logdir string, opts DirlistOptions) (DirectoryResults, error) {
	log := output.Module("DIRLIST")
	log.Start()

	sanitizedURL := stripScheme(url)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, size+" directory fuzzing"); err != nil {
			log.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

	matcher, err := newMatcher(&opts)
	if err != nil {
		log.Error("invalid matcher flags: %v", err)
		return nil, err
	}

	client := httpx.Client(timeout)

	directories, err := loadWordlist(&opts, size, client)
	if err != nil {
		log.Error("Error loading directory list: %s", err)
		return nil, err
	}
	directories = expandWords(directories, opts.Extensions)

	// -ac learns the wildcard baseline before the run so catch-all 200s drop.
	if opts.Calibrate {
		calibrate(matcher, url, client)
		if len(matcher.baselines) > 0 {
			log.Info("calibrated %d soft-404 baseline(s)", len(matcher.baselines))
		}
	}

	progress := output.NewProgress(len(directories), "fuzzing")

	var mu sync.Mutex

	results := make(DirectoryResults, 0, 64)
	pool.Each(directories, threads, func(directory string) {
		progress.Increment(directory)

		charmlog.Debugf("%s", directory)
		dirReq, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, url+"/"+directory, http.NoBody)
		if err != nil {
			charmlog.Debugf("Error creating request for %s: %s", directory, err)
			return
		}
		resp, err := client.Do(dirReq)
		if err != nil {
			charmlog.Debugf("Error %s: %s", directory, err)
			return
		}

		meta, body := readMeta(resp)
		reqURL := resp.Request.URL.String()
		resp.Body.Close()

		if !matcher.Matches(meta, body) {
			return
		}

		progress.Pause()
		log.Success("found: %s [%s] (size=%d words=%d)",
			output.Highlight.Render(directory),
			output.Status.Render(strconv.Itoa(meta.status)),
			meta.size, meta.words)
		progress.Resume()

		if logdir != "" {
			_ = logger.Write(sanitizedURL, logdir,
				fmt.Sprintf("%s [%s] size=%d words=%d\n", strconv.Itoa(meta.status), directory, meta.size, meta.words))
		}

		result := DirectoryResult{
			Url:        reqURL,
			StatusCode: meta.status,
			Size:       meta.size,
			Words:      meta.words,
		}
		mu.Lock()
		results = append(results, result)
		mu.Unlock()
	})
	progress.Done()

	log.Complete(len(results), "found")

	return results, nil
}
