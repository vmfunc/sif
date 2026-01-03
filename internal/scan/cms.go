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
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/styles"
)

type CMSResult struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func CMS(url string, timeout time.Duration, logdir string) (*CMSResult, error) {
	fmt.Println(styles.Separator.Render("🔍 Starting " + styles.Status.Render("CMS detection") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "CMS detection"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return nil, err
		}
	}

	cmslog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "CMS 🔍",
	}).With("url", url)

	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}
	bodyString := string(body)

	// WordPress
	if detectWordPress(url, client, bodyString) {
		result := &CMSResult{Name: "WordPress", Version: "Unknown"}
		cmslog.Infof("Detected CMS: %s", styles.Highlight.Render(result.Name))
		return result, nil
	}

	// Drupal
	if strings.Contains(resp.Header.Get("X-Drupal-Cache"), "HIT") || strings.Contains(bodyString, "Drupal.settings") {
		result := &CMSResult{Name: "Drupal", Version: "Unknown"}
		cmslog.Infof("Detected CMS: %s", styles.Highlight.Render(result.Name))
		return result, nil
	}

	// Joomla
	if strings.Contains(bodyString, "joomla") || strings.Contains(bodyString, "/media/system/js/core.js") {
		result := &CMSResult{Name: "Joomla", Version: "Unknown"}
		cmslog.Infof("Detected CMS: %s", styles.Highlight.Render(result.Name))
		return result, nil
	}

	cmslog.Info("No CMS detected")
	return nil, nil
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
		resp, err := client.Get(url + file)
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
