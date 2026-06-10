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
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// env var names notify reads, env-first. these mirror the conventional names so
// an operator who already exports them for other tooling gets notify for free.
const (
	envSlackWebhook   = "SLACK_WEBHOOK_URL"
	envDiscordWebhook = "DISCORD_WEBHOOK_URL"
	// the name of the env var holding the bot token, not the token itself.
	envTelegramToken = "TELEGRAM_BOT_TOKEN" //nolint:gosec // env var name, not a secret
	envTelegramChat  = "TELEGRAM_CHAT_ID"
	envWebhookURL    = "NOTIFY_WEBHOOK_URL"
)

// config holds resolved destinations for every provider. yaml tags use
// projectdiscovery/notify-compatible key names so an existing notify config file
// ports over verbatim; env supplies the same values and yaml overrides it.
type config struct {
	SlackWebhook   string `yaml:"slack_webhook_url"`
	DiscordWebhook string `yaml:"discord_webhook_url"`
	// telegram needs both a bot token and a chat id. notify spells the token
	// "telegram_api_key", so accept that key for drop-in compatibility.
	TelegramToken string `yaml:"telegram_api_key"`
	TelegramChat  string `yaml:"telegram_chat_id"`
	WebhookURL    string `yaml:"webhook_url"`
}

// loadConfig resolves notify destinations env-first, then overlays a yaml file
// when path is non-empty. yaml wins per-field so a file value overrides the
// matching env var; an unset yaml field leaves the env value intact. an empty
// path means env-only. a missing/unparseable file is an error - if the operator
// pointed -notify-config somewhere, a typo should fail loud, not silently drop.
func loadConfig(path string) (config, error) {
	cfg := config{
		SlackWebhook:   os.Getenv(envSlackWebhook),
		DiscordWebhook: os.Getenv(envDiscordWebhook),
		TelegramToken:  os.Getenv(envTelegramToken),
		TelegramChat:   os.Getenv(envTelegramChat),
		WebhookURL:     os.Getenv(envWebhookURL),
	}

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, fmt.Errorf("read config %q: %w", path, err)
	}

	// decode into a separate value so only the keys present in the file overlay
	// the env-derived defaults; a zero field in the yaml must not blank an env var.
	var file config
	if err := yaml.Unmarshal(data, &file); err != nil {
		return config{}, fmt.Errorf("parse config %q: %w", path, err)
	}
	overlay(&cfg, &file)

	return cfg, nil
}

// overlay copies non-empty fields from src onto dst. used to let a yaml file
// override env without an empty yaml key wiping out a populated env value.
func overlay(dst, src *config) {
	if src.SlackWebhook != "" {
		dst.SlackWebhook = src.SlackWebhook
	}
	if src.DiscordWebhook != "" {
		dst.DiscordWebhook = src.DiscordWebhook
	}
	if src.TelegramToken != "" {
		dst.TelegramToken = src.TelegramToken
	}
	if src.TelegramChat != "" {
		dst.TelegramChat = src.TelegramChat
	}
	if src.WebhookURL != "" {
		dst.WebhookURL = src.WebhookURL
	}
}

// providers builds the live provider list from the resolved config: a provider
// is included only when its destination is fully specified. telegram needs both
// token and chat id, so a half-configured telegram is dropped rather than POSTing
// to a broken endpoint.
func (c *config) providers() []provider {
	var out []provider
	if c.SlackWebhook != "" {
		out = append(out, &slackProvider{webhook: c.SlackWebhook})
	}
	if c.DiscordWebhook != "" {
		out = append(out, &discordProvider{webhook: c.DiscordWebhook})
	}
	if c.TelegramToken != "" && c.TelegramChat != "" {
		out = append(out, &telegramProvider{token: c.TelegramToken, chatID: c.TelegramChat})
	}
	if c.WebhookURL != "" {
		out = append(out, &webhookProvider{url: c.WebhookURL})
	}
	return out
}
