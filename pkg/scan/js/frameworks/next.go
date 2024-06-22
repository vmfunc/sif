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

	var manifestText string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		manifestText += scanner.Text()
	}

	regex, err := regexp.Compile("\\[(\"([^\"]+.js)\"(,?))")

	if err != nil {
		return nil, err
	}

	list := regex.FindAllStringSubmatch(manifestText, -1)

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
