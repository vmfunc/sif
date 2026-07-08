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
	payload := slackPayload{Text: slackText(findings)}
	return postJSON(ctx, client, s.webhook, payload)
}

// slackText builds the slack payload text so the escape-then-fence order has a
// single home the caller and tests share; skip either step and untrusted title
// text reaches the channel unneutralized.
func slackText(findings []finding.Finding) string {
	return codeBlock(slackEscape(renderFindings(findings)))
}

// slackEscape converts slack's three mrkdwn control characters to html entities.
// slack parses its angle-bracket entities - broadcast mentions <!channel>,
// <!here>, <!everyone> and user mentions <@U..> - even inside a code fence, so
// fencing alone does not contain an untrusted title: a title of "<!channel>"
// would still ping the channel. neutralizing &, < and > blocks every such entity.
// order matters: & is escaped first or a real < would become &amp;lt;.
func slackEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// codeBlock wraps body in a triple-backtick fence; both slack and discord render
// it fixed-width, which preserves the column-aligned finding lines. finding text
// is untrusted (a scraped html title can carry its own ``` run plus a @everyone),
// so any triple-backtick inside the body is neutralized first: a run of three
// would close the fence early and spill the tail out as live markdown.
func codeBlock(body string) string {
	return "```\n" + fenceGuard(body) + "```"
}

// fenceGuard breaks every run of three backticks in s with zero-width spaces so
// no ``` survives to terminate the surrounding fence. the inserted U+200B is
// invisible in both slack and discord, so the finding lines still read cleanly.
func fenceGuard(s string) string {
	return strings.ReplaceAll(s, "```", "`\u200b`\u200b`")
}
