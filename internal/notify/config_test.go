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
	"os"
	"path/filepath"
	"testing"
)

// clearNotifyEnv unsets every var loadConfig reads so a test starts from a known
// blank slate; t.Setenv("", "") still records the var for cleanup restoration.
func clearNotifyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		envSlackWebhook, envDiscordWebhook,
		envTelegramToken, envTelegramChat, envWebhookURL,
	} {
		t.Setenv(k, "")
	}
}

func TestLoadConfigEnvOnly(t *testing.T) {
	clearNotifyEnv(t)
	t.Setenv(envSlackWebhook, "https://hooks.slack.test/a")
	t.Setenv(envTelegramToken, "123:abc")
	t.Setenv(envTelegramChat, "999")

	cfg, err := loadConfig("")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.SlackWebhook != "https://hooks.slack.test/a" {
		t.Errorf("slack webhook = %q, want from env", cfg.SlackWebhook)
	}
	if cfg.TelegramToken != "123:abc" || cfg.TelegramChat != "999" {
		t.Errorf("telegram = %q/%q, want from env", cfg.TelegramToken, cfg.TelegramChat)
	}

	// slack + telegram (both halves) configured, discord/webhook empty.
	got := cfg.providers()
	if len(got) != 2 {
		t.Fatalf("providers = %d, want 2 (slack, telegram)", len(got))
	}
	wantNames := map[string]bool{"slack": false, "telegram": false}
	for _, p := range got {
		wantNames[p.name()] = true
	}
	for name, seen := range wantNames {
		if !seen {
			t.Errorf("provider %q missing", name)
		}
	}
}

func TestLoadConfigYAMLOverridesEnv(t *testing.T) {
	clearNotifyEnv(t)
	t.Setenv(envSlackWebhook, "https://env.slack.test/x")
	t.Setenv(envWebhookURL, "https://env.webhook.test/x")

	body := "" +
		"slack_webhook_url: https://file.slack.test/y\n" +
		"discord_webhook_url: https://file.discord.test/z\n"
	path := writeTempConfig(t, body)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	// yaml present -> overrides env.
	if cfg.SlackWebhook != "https://file.slack.test/y" {
		t.Errorf("slack = %q, want yaml override", cfg.SlackWebhook)
	}
	// yaml absent for webhook -> env value survives.
	if cfg.WebhookURL != "https://env.webhook.test/x" {
		t.Errorf("webhook = %q, want env value preserved", cfg.WebhookURL)
	}
	// yaml introduces discord.
	if cfg.DiscordWebhook != "https://file.discord.test/z" {
		t.Errorf("discord = %q, want from yaml", cfg.DiscordWebhook)
	}
}

func TestLoadConfigNotifyCompatibleTelegramKey(t *testing.T) {
	clearNotifyEnv(t)
	// projectdiscovery/notify spells the bot token "telegram_api_key"; assert a
	// drop-in config wires telegram from that key.
	body := "" +
		"telegram_api_key: 555:tok\n" +
		"telegram_chat_id: \"42\"\n"
	path := writeTempConfig(t, body)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.TelegramToken != "555:tok" || cfg.TelegramChat != "42" {
		t.Fatalf("telegram = %q/%q, want from notify-compatible keys", cfg.TelegramToken, cfg.TelegramChat)
	}
	if len(cfg.providers()) != 1 {
		t.Fatalf("providers = %d, want 1 (telegram)", len(cfg.providers()))
	}
}

func TestLoadConfigMissingFileErrors(t *testing.T) {
	clearNotifyEnv(t)
	if _, err := loadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("loadConfig with missing file: want error, got nil")
	}
}

func TestLoadConfigBadYAMLErrors(t *testing.T) {
	clearNotifyEnv(t)
	path := writeTempConfig(t, "slack_webhook_url: [unterminated\n")
	if _, err := loadConfig(path); err == nil {
		t.Fatal("loadConfig with malformed yaml: want error, got nil")
	}
}

func TestProvidersTelegramNeedsBothHalves(t *testing.T) {
	// token without chat id must not produce a (broken) telegram provider.
	cfg := config{TelegramToken: "tok"}
	if got := cfg.providers(); len(got) != 0 {
		t.Fatalf("providers = %d, want 0 for half-configured telegram", len(got))
	}
}

func TestProvidersEmptyConfigIsNone(t *testing.T) {
	var cfg config
	if got := cfg.providers(); len(got) != 0 {
		t.Fatalf("providers = %d, want 0 for empty config", len(got))
	}
}

// writeTempConfig writes body to a temp yaml file and returns its path.
func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notify.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}
