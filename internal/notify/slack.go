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
	"strings"

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
	payload := slackPayload{Text: codeBlock(escapeSlackText(renderFindings(findings)))}
	return postJSON(ctx, client, s.webhook, payload)
}

// escapeSlackText entity-escapes slack's three control characters (& first, so
// the later replacements don't double-escape). slack resolves a bare
// "<...|...>" as a link/mention regardless of surrounding code-fence text, so
// an unescaped title would otherwise render as a live masked link.
func escapeSlackText(body string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(body)
}

// codeBlock wraps body in a triple-backtick fence; both slack and discord render
// it fixed-width, which preserves the column-aligned finding lines. body runs
// through sanitizeFence first so attacker-controlled finding content (a title
// pulled from the scanned target) can't close the fence early and inject
// markdown/mentions outside it.
func codeBlock(body string) string {
	return "```\n" + sanitizeFence(body) + "```"
}

// sanitizeFence breaks up any triple-backtick run inside body by interleaving
// zero-width spaces between the backticks. the text still reads as backticks
// to a human but neither slack nor discord treats it as a fence boundary, so
// it can't prematurely close the code block we wrap it in.
func sanitizeFence(body string) string {
	const zwsp = "\u200b" // zero-width space
	return strings.ReplaceAll(body, "```", "`"+zwsp+"`"+zwsp+"`")
}
