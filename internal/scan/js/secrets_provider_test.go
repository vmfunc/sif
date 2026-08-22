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

package js

import (
	"fmt"
	"strings"
	"testing"
)

// split into fragments so the file itself never carries a contiguous token a
// secret scanner would flag.
var (
	provPyPI        = "pypi-AgEIcHlwaS5vcmc" + strings.Repeat("1jKlMn0p", 7)
	provOpenAILeg   = "sk-" + "aB3dEfGh1jKlMn0pQrSt" + "T3BlbkFJ" + "uVwXyZ012345abcdefgh"
	provOpenAIProj  = "sk-proj-" + "aB3dEfGh1jKlMn0pQrStUvWxYz012345abcd"
	provSquare      = "sq0atp-" + "aB3dEfGh1jKlMn0pQrSt-U"
	provMailgun     = "key-" + "0123456789abcdef0123456789abcdef"
	provDiscordBot  = "M" + "TIzNDU2Nzg5MDEyMzQ1Njc4" + "." + "GaBcDe" + "." + "aB3dEfGh1jKlMn0pQrStUvWxYz012345abcdef"
	provDiscordHook = "discord.com/api/webhooks/" + "123456789012345678" + "/" + strings.Repeat("aB3dEfGh1j", 6) + "abcdefgh"
	provNewRelic    = "NRAK-" + "AB3DEFGH1JKLMN0PQRSTUVWXYZZ"
	provCloudinary  = "cloudinary://" + "123456789012345" + ":" + "aB3dEfGh1jKlMn0pQrStUvWxYz" + "@my-cloud"
	provMongoURI    = "mongodb+srv://" + "dbadmin" + ":" + "tR7q!zK2vLp9xC" + "@cluster0.example.mongodb.net/prod"
	provMongoPlace  = "mongodb://" + "user" + ":" + "password" + "@localhost:27017/app"

	// a real jwt (rfc 7519 example header/payload), signature is dummy.
	provJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
		".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0" +
		".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

// each provider rule added on top of the existing bank, plus the two cases the
// shape alone cannot decide: a dotted base64url blob that is not a jwt, and a
// connection string whose password is a documentation placeholder.
func TestScanSecretsProviderRules(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantRule string // "" means the content must produce no match
	}{
		{
			name:     "pypi api token",
			content:  fmt.Sprintf(`password = %q`, provPyPI),
			wantRule: "pypi api token",
		},
		{
			name:     "openai legacy api key",
			content:  fmt.Sprintf(`OPENAI_API_KEY=%q`, provOpenAILeg),
			wantRule: "openai api key",
		},
		{
			name:     "openai project api key",
			content:  fmt.Sprintf(`OPENAI_API_KEY=%q`, provOpenAIProj),
			wantRule: "openai project api key",
		},
		{
			name:     "square access token",
			content:  fmt.Sprintf(`squareToken = %q`, provSquare),
			wantRule: "square access token",
		},
		{
			name:     "mailgun api key",
			content:  fmt.Sprintf(`MAILGUN_KEY=%q`, provMailgun),
			wantRule: "mailgun api key",
		},
		{
			name:     "discord bot token",
			content:  fmt.Sprintf(`client.login(%q)`, provDiscordBot),
			wantRule: "discord bot token",
		},
		{
			name:     "discord webhook url",
			content:  fmt.Sprintf(`fetch("https://%s")`, provDiscordHook),
			wantRule: "discord webhook url",
		},
		{
			name:     "new relic license key",
			content:  fmt.Sprintf(`NEW_RELIC_LICENSE_KEY=%q`, provNewRelic),
			wantRule: "new relic license key",
		},
		{
			name:     "cloudinary url",
			content:  fmt.Sprintf(`CLOUDINARY_URL=%q`, provCloudinary),
			wantRule: "cloudinary url",
		},
		{
			name:     "jwt with a valid header",
			content:  fmt.Sprintf(`const token = %q;`, provJWT),
			wantRule: "jwt",
		},
		{
			name:    "three dotted base64url blobs without a jwt header",
			content: `const s = "eyJhYmNkZWZnaGlq.aGVsbG93b3JsZDEy.c2lnbmF0dXJlYmxvYmhlcmU";`,
		},
		{
			name:     "connection string with real credentials",
			content:  fmt.Sprintf(`const uri = %q;`, provMongoURI),
			wantRule: "database connection string",
		},
		{
			name:    "connection string with a placeholder password",
			content: fmt.Sprintf(`// example: %s`, provMongoPlace),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScanSecrets(tt.content, "https://example.test/app.js")

			if tt.wantRule == "" {
				if len(got) != 0 {
					t.Fatalf("got %d matches (%s), want none", len(got), got[0].Rule)
				}
				return
			}

			var rules []string
			for i := range got {
				rules = append(rules, got[i].Rule)
				if got[i].Rule == tt.wantRule {
					return
				}
			}
			t.Fatalf("rule %q did not fire, got %v", tt.wantRule, rules)
		})
	}
}

// the rules added here must not overlap each other or the provider-prefixed
// rules already in the bank: one credential in one script is one finding, not
// two. the generic assignment rule is excluded because it claims any quoted
// high-entropy value behind a token/password/secret keyword, so it already
// doubles up with every prefixed rule on main; that is pre-existing and not
// something these rules introduce.
func TestProviderRulesDoNotDuplicateExistingCoverage(t *testing.T) {
	content := strings.Join([]string{
		fmt.Sprintf(`password = %q`, provPyPI),
		fmt.Sprintf(`OPENAI_API_KEY=%q`, provOpenAILeg),
		fmt.Sprintf(`squareToken = %q`, provSquare),
		fmt.Sprintf(`MAILGUN_KEY=%q`, provMailgun),
		fmt.Sprintf(`client.login(%q)`, provDiscordBot),
		fmt.Sprintf(`NEW_RELIC_LICENSE_KEY=%q`, provNewRelic),
		fmt.Sprintf(`CLOUDINARY_URL=%q`, provCloudinary),
		fmt.Sprintf(`const token = %q;`, provJWT),
		fmt.Sprintf(`const uri = %q;`, provMongoURI),
	}, "\n")

	seen := make(map[string]int)
	for _, m := range ScanSecrets(content, "https://example.test/app.js") {
		if m.Rule == "generic secret assignment" {
			continue
		}
		seen[m.Match]++
	}

	for value, n := range seen {
		if n > 1 {
			t.Errorf("value %q reported %d times, want 1", value, n)
		}
	}
}
