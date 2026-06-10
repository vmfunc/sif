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

// discordProvider posts to a discord webhook. discord's incoming-webhook body
// keys the message on "content" (slack uses "text"); same code-block wrapping so
// the finding columns line up in the channel.
type discordProvider struct {
	webhook string
}

func (d *discordProvider) name() string { return "discord" }

// discordPayload is the minimal webhook body: a single content field.
type discordPayload struct {
	Content string `json:"content"`
}

func (d *discordProvider) send(ctx context.Context, client *http.Client, findings []finding.Finding) error {
	payload := discordPayload{Content: codeBlock(renderFindings(findings))}
	return postJSON(ctx, client, d.webhook, payload)
}
