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
	"context"
	"net/http"

	"github.com/dropalldatabases/sif/internal/finding"
)

// webhookProvider posts a structured json payload to an arbitrary endpoint. unlike
// the chat sinks it carries the findings as data, not a prerendered blob, so
// downstream automation (a siem, a bot, ci) keys off the fields directly.
type webhookProvider struct {
	url string
}

func (w *webhookProvider) name() string { return "webhook" }

// webhookFinding is the per-item wire shape: the normalized Finding fields with
// severity flattened to its canonical string so a json consumer never sees the
// internal integer rank.
type webhookFinding struct {
	Target   string `json:"target"`
	Module   string `json:"module"`
	Severity string `json:"severity"`
	Key      string `json:"key"`
	Title    string `json:"title"`
	Raw      string `json:"raw,omitempty"`
}

// webhookPayload wraps the batch with a count so a consumer can size buffers /
// assert completeness without walking the slice first.
type webhookPayload struct {
	Count    int              `json:"count"`
	Findings []webhookFinding `json:"findings"`
}

func (w *webhookProvider) send(ctx context.Context, client *http.Client, findings []finding.Finding) error {
	items := make([]webhookFinding, 0, len(findings))
	for i := 0; i < len(findings); i++ {
		f := findings[i]
		items = append(items, webhookFinding{
			Target:   f.Target,
			Module:   f.Module,
			Severity: f.Severity.String(),
			Key:      f.Key,
			Title:    f.Title,
			Raw:      f.Raw,
		})
	}
	payload := webhookPayload{Count: len(items), Findings: items}
	return postJSON(ctx, client, w.url, payload)
}
