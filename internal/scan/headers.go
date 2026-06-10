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
	"net/http"
	"time"

	"github.com/dropalldatabases/sif/internal/httpx"
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

	sanitizedURL := stripScheme(url)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "HTTP Header Analysis"); err != nil {
			log.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

	client := httpx.Client(timeout)

	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req) //nolint:bodyclose // drained and closed via httpx.DrainClose
	if err != nil {
		return nil, err
	}
	// header-only scan: drain on close so the conn is returned to the pool.
	defer httpx.DrainClose(resp)

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
