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

// sanitizeFence separates every backtick in body from the next with a
// zero-width space. the text still reads as backticks to a human but no two
// are ever adjacent, so neither slack nor discord sees a fence boundary and
// attacker content can't close the code block we wrap it in.
//
// breaking exact triples instead would leave a trailing bare backtick, and any
// run of length \u2261 2 mod 3 (5, 8, 11...) would reform a contiguous triple.
func sanitizeFence(body string) string {
	const zwsp = "\u200b" // zero-width space
	return strings.ReplaceAll(body, "`", "`"+zwsp)
}
