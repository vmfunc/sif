/*
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                                  SIF                                         ║
║                                                                              ║
║        Blazing-fast pentesting suite written in Go                           ║
║                                                                              ║
║        Copyright (c) 2023-2024 vmfunc, xyzeva, lunchcat contributors         ║
║                    and other sif contributors.                               ║
║                                                                              ║
║                                                                              ║
║        Use of this tool is restricted to research and educational            ║
║        purposes only. Usage in a production environment outside              ║
║        of these categories is strictly prohibited.                           ║
║                                                                              ║
║        Any person or entity wishing to use this tool outside of              ║
║        research or educational purposes must purchase a license              ║
║        from https://lunchcat.dev                                             ║
║                                                                              ║
║        For more information, visit: https://github.com/lunchcat/sif          ║ 
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
*/

package scan

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"os"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/dropalldatabases/sif/pkg/logger"
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

	body, err := io.ReadAll(resp.Body)
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
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusFound {
				return true
			}
		}
	}

	return false
}
