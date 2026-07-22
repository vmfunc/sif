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
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	charmlog "github.com/charmbracelet/log"
	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
	"github.com/vmfunc/sif/internal/pool"
)

// gitURL is a var so integration tests can repoint it at a fixture.
var gitURL = "https://raw.githubusercontent.com/vmfunc/sif-runtime/main/git/"

const gitFile = "git.txt"

// a 200 alone proves nothing: a server that answers every path with the same
// catch-all page reports the whole git list as exposed. gitValidateCap bounds
// how much of the body we read to confirm the response is the requested git
// artifact and not that shell.
const gitValidateCap = 8 << 10

var (
	// a git object name is a sha1 (40 hex) or, on sha256 repos, 64 hex. refs and
	// a detached HEAD hold exactly this and nothing else.
	gitObjectName = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	// a reflog line opens with "<old-sha> <new-sha> "; the zero sha is valid for
	// the first entry, so match the shape rather than reject all-zero hashes.
	gitReflogLine = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})? [0-9a-f]{40}`)
)

// looksLikeGit reports whether body is plausibly the git artifact at repoPath
// rather than a catch-all 200 page. paths with a recognizable shape (HEAD, the
// index magic, the config header, refs and reflogs) are matched positively; the
// rest (.gitignore and anything new in the list) fall back to rejecting the
// html/json bodies a soft-404 or spa shell hands back.
func looksLikeGit(repoPath string, body []byte) bool {
	text := strings.TrimSpace(string(body))
	switch {
	case strings.Contains(repoPath, "/logs/"):
		// reflog lives under .git/logs/, including .git/logs/refs/..., so this
		// must be checked before the /refs/ case below.
		return gitReflogLine.MatchString(text)
	case strings.HasSuffix(repoPath, "/index"):
		return strings.HasPrefix(string(body), "DIRC")
	case strings.HasSuffix(repoPath, "/config"):
		return strings.Contains(text, "[core]")
	case strings.HasSuffix(repoPath, "/HEAD"):
		return strings.HasPrefix(text, "ref:") || gitObjectName.MatchString(text)
	case strings.Contains(repoPath, "/refs/"):
		return gitObjectName.MatchString(text)
	default:
		return shapelessGitArtifact(text, body)
	}
}

// shapelessGitArtifact is the fallback for paths with no fixed shape (.gitignore
// and anything new in the list). a real artifact is neither html nor json; the
// leading-byte rejects also catch a shell whose body is truncated past the read
// cap. a '[' is ambiguous - a json array shell, but also a valid .gitignore
// character class like "[Bb]in/" - so json validity, not the bare byte, decides.
func shapelessGitArtifact(text string, body []byte) bool {
	switch {
	case text == "":
		return false
	case strings.HasPrefix(text, "<"), strings.HasPrefix(text, "{"):
		return false
	case strings.HasPrefix(text, "["):
		return !json.Valid(body)
	default:
		return true
	}
}

func Git(url string, timeout time.Duration, threads int, logdir string) ([]string, error) {
	log := output.Module("GIT")
	log.Start()

	spin := output.NewSpinner("Scanning for exposed git repositories")
	spin.Start()

	sanitizedURL := stripScheme(url)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "git directory fuzzing"); err != nil {
			spin.Stop()
			log.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

	client := httpx.Client(timeout)

	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, gitURL+gitFile, http.NoBody)
	if err != nil {
		spin.Stop()
		log.Error("Error creating git list request: %s", err)
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		spin.Stop()
		log.Error("Error downloading git list: %s", err)
		return nil, err
	}
	defer resp.Body.Close()
	var gitUrls []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		gitUrls = append(gitUrls, scanner.Text())
	}

	var mu sync.Mutex

	foundUrls := []string{}
	pool.Each(gitUrls, threads, func(repourl string) {
		charmlog.Debugf("%s", repourl)
		gitReq, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, url+"/"+repourl, http.NoBody)
		if err != nil {
			charmlog.Debugf("Error creating request for %s: %s", repourl, err)
			return
		}
		resp, err := client.Do(gitReq) //nolint:bodyclose // drained and closed via httpx.DrainClose
		if err != nil {
			charmlog.Debugf("Error %s: %s", repourl, err)
			return
		}
		if resp.StatusCode != 200 {
			httpx.DrainClose(resp)
			return
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, gitValidateCap))
		foundURL := resp.Request.URL.String()
		httpx.DrainClose(resp)
		if err != nil {
			charmlog.Debugf("Error reading %s: %s", repourl, err)
			return
		}
		if !looksLikeGit(repourl, body) {
			return
		}

		spin.Stop()
		log.Success("Git found at %s [%s]", output.Highlight.Render(repourl), output.Status.Render(strconv.Itoa(resp.StatusCode)))
		spin.Start()
		if logdir != "" {
			logger.Write(sanitizedURL, logdir, strconv.Itoa(resp.StatusCode)+" git found at ["+repourl+"]\n")
		}

		mu.Lock()
		foundUrls = append(foundUrls, foundURL)
		mu.Unlock()
	})

	spin.Stop()
	log.Complete(len(foundUrls), "found")

	return foundUrls, nil
}
