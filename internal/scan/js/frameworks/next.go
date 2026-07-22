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

/*
	What we are doing is abusing a internal file in Next.js pages router called
	_buildManifest.js which lists all routes and script files ever referenced in
	the application within next.js, this allows us to optimise and not bruteforce
	directories for routes and instead get all of them at once.

	We are currently parsing this js file with regexes but that should ideally be
	replaced soon.
*/

package frameworks

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/output"
)

// nextPagesRegex matches JavaScript file references in Next.js build manifest.
var nextPagesRegex = regexp.MustCompile(`\[("([^"]+\.js)"(,?))`)

// maxManifestSize caps the build manifest read so a huge or hostile file
// cannot exhaust memory.
const maxManifestSize = 5 * 1024 * 1024

func GetPagesRouterScripts(scriptUrl string, timeout time.Duration) ([]string, error) {
	baseUrl, err := urlutil.Parse(scriptUrl)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, scriptUrl, http.NoBody)
	if err != nil {
		output.Error("%v", err)
		return nil, err
	}

	// use the caller's scan timeout so a slow or hostile manifest host cannot
	// hang the whole scan; a zero timeout would read with no deadline.
	resp, err := httpx.Client(timeout).Do(req)
	if err != nil {
		output.Error("%v", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestSize))
	if err != nil {
		output.Error("%v", err)
		return nil, err
	}
	// the manifest ships minified on one line; strip line breaks so the regex
	// treats a (rare) pretty-printed one the same as the minified form.
	manifestText := strings.NewReplacer("\r", "", "\n", "").Replace(string(body))

	list := nextPagesRegex.FindAllStringSubmatch(manifestText, -1)

	var scripts []string

	for _, el := range list {
		var script = strings.ReplaceAll(el[2], "\\u002F", "/")
		url, err := urlutil.Parse(script)
		if err != nil {
			continue
		}

		if url.IsRelative {
			url.Host = baseUrl.Host
			url.Scheme = baseUrl.Scheme
			url.Path = "/_next/" + url.Path
		}
		scripts = append(scripts, url.String())
	}

	return scripts, nil
}
