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
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/output"
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

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "CMS detection"); err != nil {
			spin.Stop()
			log.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

	client := &http.Client{
		Timeout: timeout,
	}

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
	if strings.Contains(resp.Header.Get("X-Drupal-Cache"), "HIT") || strings.Contains(bodyString, "Drupal.settings") {
		spin.Stop()
		result := &CMSResult{Name: "Drupal", Version: "Unknown"}
		log.Success("Detected CMS: %s", output.Highlight.Render(result.Name))
		log.Complete(1, "detected")
		return result, nil
	}

	// Joomla
	if strings.Contains(bodyString, "joomla") || strings.Contains(bodyString, "/media/system/js/core.js") {
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
	// Check for common WordPress indicators in the HTML
	wpIndicators := []string{
		"wp-content",
		"wp-includes",
		"wp-json",
		"wordpress",
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
		if err == nil {
			found := resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound
			resp.Body.Close()
			if found {
				return true
			}
		}
	}

	return false
}
