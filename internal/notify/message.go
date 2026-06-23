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

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/vmfunc/sif/internal/finding"
	"github.com/vmfunc/sif/internal/httpx"
)

// contentTypeJSON is the body type every provider POSTs; all four speak json.
const contentTypeJSON = "application/json"

// messageHeader prefixes the rendered finding block. kept terse - chat sinks
// truncate, so the count and lead-in carry the signal.
const messageHeader = "sif found %d finding(s):"

// renderFindings turns a batch into a single plain-text block, one finding per
// line in the same "[severity] target module title" shape as the -silent sink so
// a reader sees identical lines across stdout and chat. a strings.Builder keeps
// the per-line concat to one allocation path.
func renderFindings(findings []finding.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, messageHeader, len(findings))
	b.WriteByte('\n')
	for i := 0; i < len(findings); i++ {
		b.WriteString(findings[i].Line())
		b.WriteByte('\n')
	}
	return b.String()
}

// postJSON marshals payload and POSTs it to url through the shared client. it
// drains+closes the response so the conn returns to httpx's pool, and treats any
// non-2xx as a delivery failure so a 4xx from a bad webhook surfaces loudly.
func postJSON(ctx context.Context, client *http.Client, url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)

	resp, err := client.Do(req) //nolint:bodyclose // drained and closed via httpx.DrainClose
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer httpx.DrainClose(resp)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}
