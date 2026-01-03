/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (Celeste Hickenlooper), xyzeva,                        :
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
	"bufio"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	urlutil "github.com/projectdiscovery/utils/url"
)

// nextPagesRegex matches JavaScript file references in Next.js build manifest.
var nextPagesRegex = regexp.MustCompile(`\[("([^"]+\.js)"(,?))`)

func GetPagesRouterScripts(scriptUrl string) ([]string, error) {
	baseUrl, err := urlutil.Parse(scriptUrl)
	if err != nil {
		return nil, err
	}

	resp, err := http.Get(scriptUrl)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer resp.Body.Close()

	var sb strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
	}
	manifestText := sb.String()

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
