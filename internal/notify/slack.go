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

	"github.com/vmfunc/sif/internal/finding"
)

// slackProvider posts to a slack incoming webhook. the webhook url already pins
// the channel, so the payload is just the rendered text in slack's mrkdwn-aware
// "text" field wrapped in a code block to keep the fixed-width finding lines.
type slackProvider struct {
	webhook string
}

func (s *slackProvider) name() string { return "slack" }

// slackPayload is the minimal incoming-webhook body: a single text field.
type slackPayload struct {
	Text string `json:"text"`
}

func (s *slackProvider) send(ctx context.Context, client *http.Client, findings []finding.Finding) error {
	payload := slackPayload{Text: codeBlock(renderFindings(findings))}
	return postJSON(ctx, client, s.webhook, payload)
}

// codeBlock wraps body in a triple-backtick fence; both slack and discord render
// it fixed-width, which preserves the column-aligned finding lines.
func codeBlock(body string) string {
	return "```\n" + body + "```"
}
