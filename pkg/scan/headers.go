/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package scan

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/dropalldatabases/sif/pkg/logger"
)

type HeaderResult struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func Headers(url string, timeout time.Duration, logdir string) ([]HeaderResult, error) {
	fmt.Println(styles.Separator.Render("🔍 Starting " + styles.Status.Render("HTTP Header Analysis") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "HTTP Header Analysis"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return nil, err
		}
	}

	headerlog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Headers 🔍",
	}).With("url", url)

	client := &http.Client{
		Timeout: timeout,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var results []HeaderResult

	for name, values := range resp.Header {
		for _, value := range values {
			results = append(results, HeaderResult{Name: name, Value: value})
			headerlog.Infof("%s: %s", styles.Highlight.Render(name), value)
			if logdir != "" {
				logger.Write(sanitizedURL, logdir, fmt.Sprintf("%s: %s\n", name, value))
			}
		}
	}

	return results, nil
}
