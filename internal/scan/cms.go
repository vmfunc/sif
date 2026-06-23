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
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
)

type CMSResult struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func CMS(url string, timeout time.Duration, logdir string) (*CMSResult, error) {
	log := output.Module("CMS")
	log.Start()

	spin := output.NewSpinner("Detecting content management system")
	spin.Start()

	sanitizedURL := stripScheme(url)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "CMS detection"); err != nil {
			spin.Stop()
			log.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

	client := httpx.Client(timeout)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	if err != nil {
		spin.Stop()
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		spin.Stop()
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		spin.Stop()
		return nil, err
	}
	bodyString := string(body)

	// WordPress
	if detectWordPress(url, client, bodyString) {
		spin.Stop()
		result := &CMSResult{Name: "WordPress", Version: "Unknown"}
		log.Success("Detected CMS: %s", output.Highlight.Render(result.Name))
		log.Complete(1, "detected")
		return result, nil
	}

	// Drupal
	if detectDrupal(resp.Header, bodyString) {
		spin.Stop()
		result := &CMSResult{Name: "Drupal", Version: "Unknown"}
		log.Success("Detected CMS: %s", output.Highlight.Render(result.Name))
		log.Complete(1, "detected")
		return result, nil
	}

	// Joomla
	if detectJoomla(bodyString) {
		spin.Stop()
		result := &CMSResult{Name: "Joomla", Version: "Unknown"}
		log.Success("Detected CMS: %s", output.Highlight.Render(result.Name))
		log.Complete(1, "detected")
		return result, nil
	}

	spin.Stop()
	log.Info("No CMS detected")
	log.Complete(0, "detected")
	return nil, nil //nolint:nilnil // no CMS found is not an error
}

func detectWordPress(url string, client *http.Client, bodyString string) bool {
	// wordpress asset paths only; the bare word "wordpress" matched pages that
	// merely mention it (wp-hosting marketing), so it is dropped.
	wpIndicators := []string{
		"wp-content",
		"wp-includes",
		"wp-json",
	}

	for _, indicator := range wpIndicators {
		if strings.Contains(bodyString, indicator) {
			return true
		}
	}

	// Check for WordPress-specific files
	wpFiles := []string{
		"/wp-login.php",
		"/wp-admin/",
		"/wp-config.php",
	}

	for _, file := range wpFiles {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url+file, http.NoBody)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
			continue
		}
		// the client follows redirects, so soft-404 and catch-all sites also land
		// here with a 200; require an actual WordPress marker in the body.
		probeBody := string(body)
		for _, indicator := range wpIndicators {
			if strings.Contains(probeBody, indicator) {
				return true
			}
		}
	}

	return false
}

// detectJoomla keys on the capital Joomla! generator and joomla asset paths. a
// bare "joomla" mention (the old check) matched marketing pages, so it is gone.
func detectJoomla(body string) bool {
	return strings.Contains(body, `generator" content="Joomla!`) ||
		strings.Contains(body, "/media/vendor/joomla") ||
		strings.Contains(body, "/media/system/js/core.js")
}

// detectDrupal reports whether the response looks like Drupal. the X-Drupal-* and
// X-Generator headers survive cdn caching when the body markers do not, and an
// X-Drupal-Cache of any value (even MISS) is a tell.
func detectDrupal(header http.Header, body string) bool {
	return strings.Contains(header.Get("X-Generator"), "Drupal") ||
		header.Get("X-Drupal-Cache") != "" ||
		header.Get("X-Drupal-Dynamic-Cache") != "" ||
		strings.Contains(body, "Drupal.settings") ||
		strings.Contains(body, "drupalSettings")
}
