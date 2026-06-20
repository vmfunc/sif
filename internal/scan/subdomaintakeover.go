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
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/httpx"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/pool"
	"github.com/dropalldatabases/sif/internal/styles"
)

// SubdomainTakeoverResult represents the outcome of a subdomain takeover vulnerability check.
// It includes the subdomain tested, whether it's vulnerable, and the potentially vulnerable service.
type SubdomainTakeoverResult struct {
	Subdomain  string `json:"subdomain"`
	Vulnerable bool   `json:"vulnerable"`
	Service    string `json:"service,omitempty"`
}

// takeoverProviders maps a takeoverable third-party's cname apex to its service
// name. a "no such host" on a subdomain only counts as a dangling-cname takeover
// when the cname points at one of these and the target is unclaimed - a cname
// to anything else (or to the host itself) is a normal record, not a finding.
var takeoverProviders = map[string]string{
	"github.io":             "GitHub Pages",
	"herokuapp.com":         "Heroku",
	"herokudns.com":         "Heroku",
	"myshopify.com":         "Shopify",
	"wordpress.com":         "WordPress",
	"s3.amazonaws.com":      "Amazon S3",
	"ghost.io":              "Ghost",
	"pantheonsite.io":       "Pantheon",
	"zendesk.com":           "Zendesk",
	"surge.sh":              "Surge",
	"bitbucket.io":          "Bitbucket",
	"fastly.net":            "Fastly",
	"helpscoutdocs.com":     "Helpscout",
	"cargocollective.com":   "Cargo",
	"uservoice.com":         "Uservoice",
	"webflow.io":            "Webflow",
	"readthedocs.io":        "ReadTheDocs",
	"azurewebsites.net":     "Azure",
	"cloudapp.net":          "Azure",
	"trafficmanager.net":    "Azure",
	"blob.core.windows.net": "Azure",
	"netlify.app":           "Netlify",
	"netlify.com":           "Netlify",
}

// SubdomainTakeover checks dnsResults for dangling subdomains pointing at
// unclaimed third-party services.
func SubdomainTakeover(url string, dnsResults []string, timeout time.Duration, threads int, logdir string) ([]SubdomainTakeoverResult, error) {
	fmt.Println(styles.Separator.Render("Starting " + styles.Status.Render("Subdomain Takeover Vulnerability Check") + "..."))

	sanitizedURL := stripScheme(url)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "Subdomain Takeover Vulnerability Check"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return nil, err
		}
	}

	subdomainlog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Subdomain Takeover",
	})

	client := httpx.Client(timeout)

	// buffered to the full candidate count so a send never blocks: Each only
	// returns once every worker is done, and the channel is drained afterwards.
	resultsChan := make(chan SubdomainTakeoverResult, len(dnsResults))

	pool.Each(dnsResults, threads, func(subdomain string) {
		vulnerable, service := checkSubdomainTakeover(subdomain, client)
		result := SubdomainTakeoverResult{
			Subdomain:  subdomain,
			Vulnerable: vulnerable,
			Service:    service,
		}
		resultsChan <- result

		if vulnerable {
			subdomainlog.Warnf("Potential subdomain takeover: %s (%s)", styles.Highlight.Render(subdomain), service)
			if logdir != "" {
				logger.Write(sanitizedURL, logdir, fmt.Sprintf("Potential subdomain takeover: %s (%s)\n", subdomain, service))
			}
		} else {
			subdomainlog.Infof("Subdomain not vulnerable: %s", subdomain)
		}
	})
	close(resultsChan)

	var results []SubdomainTakeoverResult
	for result := range resultsChan {
		results = append(results, result)
	}

	return results, nil
}

// danglingProvider reports whether cname points off-host at a known
// takeoverable provider. a self-referential cname (LookupCNAME echoing an A
// record back as the host) is rejected, since that's a live host, not a
// dangling pointer.
func danglingProvider(subdomain, cname string) (string, bool) {
	// LookupCNAME returns a fqdn with a trailing dot; strip it so suffix and
	// self-reference checks compare like-for-like.
	target := strings.ToLower(strings.TrimSuffix(cname, "."))
	host := strings.ToLower(strings.TrimSuffix(subdomain, "."))
	if target == "" || target == host {
		return "", false
	}

	for apex, service := range takeoverProviders {
		if target == apex || strings.HasSuffix(target, "."+apex) {
			return service, true
		}
	}
	return "", false
}

func checkSubdomainTakeover(subdomain string, client *http.Client) (bool, string) {
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, "http://"+subdomain, http.NoBody)
	if err != nil {
		return false, ""
	}
	resp, err := client.Do(req)
	if err != nil {
		// a dead host only matters if its cname still points at an unclaimed
		// third-party service. LookupCNAME echoes the host back for plain A
		// records, so "any cname" is not a signal - the cname must resolve to a
		// known takeoverable provider and not be the host itself.
		if strings.Contains(err.Error(), "no such host") {
			cname, lookupErr := net.DefaultResolver.LookupCNAME(context.TODO(), subdomain)
			if lookupErr == nil {
				if service, ok := danglingProvider(subdomain, cname); ok {
					return true, service + " (Dangling CNAME)"
				}
			}
		}
		return false, ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return false, ""
	}
	bodyString := string(body)

	// Check for common takeover signatures in the response
	signatures := map[string]string{
		"GitHub Pages":    "There isn't a GitHub Pages site here.",
		"Heroku":          "No such app",
		"Shopify":         "Sorry, this shop is currently unavailable.",
		"Tumblr":          "There's nothing here.",
		"WordPress":       "Do you want to register *.wordpress.com?",
		"Amazon S3":       "The specified bucket does not exist",
		"Bitbucket":       "Repository not found",
		"Ghost":           "The thing you were looking for is no longer here, or never was",
		"Pantheon":        "The gods are wise, but do not know of the site which you seek.",
		"Fastly":          "Fastly error: unknown domain",
		"Zendesk":         "Help Center Closed",
		"Helpjuice":       "We could not find what you're looking for.",
		"Helpscout":       "No settings were found for this company:",
		"Cargo":           "If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel.",
		"Uservoice":       "This UserVoice subdomain is currently available!",
		"Surge":           "project not found",
		"Intercom":        "This page is reserved for artistic dogs.",
		"Webflow":         "The page you are looking for doesn't exist or has been moved.",
		"Wishpond":        "https://www.wishpond.com/404?campaign=true",
		"Aftership":       "Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist.",
		"Aha":             "There is no portal here ... sending you back to Aha!",
		"Brightcove":      "<p class=\"bc-gallery-error-code\">Error Code: 404</p>",
		"Bigcartel":       "<h1>Oops! We couldn&#8217;t find that page.</h1>",
		"Compaignmonitor": "Double check the URL or <a href=\"mailto:help@createsend.com",
		"Acquia":          "The site you are looking for could not be found.",
		"Proposify":       "If you need immediate assistance, please contact <a href=\"mailto:support@proposify.biz",
		"Simplebooklet":   "We can't find this <a href=\"https://simplebooklet.com",
		"Getresponse":     "With GetResponse Landing Pages, lead generation has never been easier",
		"Vend":            "Looks like you've traveled too far into cyberspace.",
		"Jetbrains":       "is not a registered InCloud YouTrack.",
		"Azure":           "404 Web Site not found.",
	}

	for service, signature := range signatures {
		if strings.Contains(bodyString, signature) {
			return true, service
		}
	}

	return false, ""
}
