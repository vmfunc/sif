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

package scan

import (
	"fmt"
	"github.com/charmbracelet/log"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/styles"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// SubdomainTakeoverResult represents the outcome of a subdomain takeover vulnerability check.
// It includes the subdomain tested, whether it's vulnerable, and the potentially vulnerable service.
type SubdomainTakeoverResult struct {
	Subdomain  string `json:"subdomain"`
	Vulnerable bool   `json:"vulnerable"`
	Service    string `json:"service,omitempty"`
}

// SubdomainTakeover checks for potential subdomain takeover vulnerabilities.
//
// Parameters:
//   - url: the target URL to scan
//   - dnsResults: a slice of subdomains to check (typically from Dnslist function)
//   - timeout: maximum duration for each subdomain check
//   - threads: number of concurrent threads to use
//   - logdir: directory to store log files (empty string for no logging)
//
// Returns:
//   - []SubdomainTakeoverResult: a slice of results for each checked subdomain
//   - error: any error encountered during the scan
func SubdomainTakeover(url string, dnsResults []string, timeout time.Duration, threads int, logdir string) ([]SubdomainTakeoverResult, error) {
	fmt.Println(styles.Separator.Render("🔍 Starting " + styles.Status.Render("Subdomain Takeover Vulnerability Check") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "Subdomain Takeover Vulnerability Check"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return nil, err
		}
	}

	subdomainlog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Subdomain Takeover 🔍",
	})

	client := &http.Client{
		Timeout: timeout,
	}

	var wg sync.WaitGroup
	wg.Add(threads)

	resultsChan := make(chan SubdomainTakeoverResult, len(dnsResults))

	for thread := 0; thread < threads; thread++ {
		go func(thread int) {
			defer wg.Done()

			for i, subdomain := range dnsResults {
				if i%threads != thread {
					continue
				}

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
			}
		}(thread)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []SubdomainTakeoverResult
	for result := range resultsChan {
		results = append(results, result)
	}

	return results, nil
}

func checkSubdomainTakeover(subdomain string, client *http.Client) (bool, string) {
	resp, err := client.Get("http://" + subdomain)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			// Check if CNAME exists
			cname, err := net.LookupCNAME(subdomain)
			if err == nil && cname != "" {
				return true, "Dangling CNAME"
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
		"Teamwork":        "Oops - We didn't find your site.",
		"Helpjuice":       "We could not find what you're looking for.",
		"Helpscout":       "No settings were found for this company:",
		"Cargo":           "If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS control panel.",
		"Uservoice":       "This UserVoice subdomain is currently available!",
		"Surge":           "project not found",
		"Intercom":        "This page is reserved for artistic dogs.",
		"Webflow":         "The page you are looking for doesn't exist or has been moved.",
		"Kajabi":          "The page you were looking for doesn't exist.",
		"Thinkific":       "You may have mistyped the address or the page may have moved.",
		"Tave":            "Sorry, this page is no longer available.",
		"Wishpond":        "https://www.wishpond.com/404?campaign=true",
		"Aftership":       "Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist.",
		"Aha":             "There is no portal here ... sending you back to Aha!",
		"Brightcove":      "<p class=\"bc-gallery-error-code\">Error Code: 404</p>",
		"Bigcartel":       "<h1>Oops! We couldn&#8217;t find that page.</h1>",
		"Activecompaign":  "alt=\"LIGHTTPD - fly light.\"",
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
