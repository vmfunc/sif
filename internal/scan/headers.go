/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (vmfunc), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package scan

import (
	"net/http"
	"strings"
	"time"

	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/output"
)

type HeaderResult struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func Headers(url string, timeout time.Duration, logdir string) ([]HeaderResult, error) {
	log := output.Module("HEADERS")
	log.Start()

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "HTTP Header Analysis"); err != nil {
			log.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

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
			log.Info("%s: %s", output.Highlight.Render(name), value)
			if logdir != "" {
				logger.Write(sanitizedURL, logdir, name+": "+value+"\n")
			}
		}
	}

	log.Complete(len(results), "found")
	return results, nil
}
