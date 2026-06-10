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

// telegramAPIBase is the bot api root. it's a var so tests can repoint it at an
// httptest server; the token is appended path-side per telegram's scheme.
var telegramAPIBase = "https://api.telegram.org"

// telegramProvider posts via the bot api's sendMessage. unlike slack/discord the
// destination isn't a single opaque webhook: it needs the bot token (in the url
// path) plus the chat id (in the body).
type telegramProvider struct {
	token  string
	chatID string
}

func (t *telegramProvider) name() string { return "telegram" }

// telegramPayload is the sendMessage body. parse_mode "MarkdownV2" would force
// escaping every special char in the finding lines, so we send plain text and
// let the lines stand as-is.
type telegramPayload struct {
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
}

func (t *telegramProvider) send(ctx context.Context, client *http.Client, findings []finding.Finding) error {
	endpoint := telegramAPIBase + "/bot" + t.token + "/sendMessage"
	payload := telegramPayload{ChatID: t.chatID, Text: renderFindings(findings)}
	return postJSON(ctx, client, endpoint, payload)
}
