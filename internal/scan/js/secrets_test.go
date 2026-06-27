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

// the fake tokens below are assembled from two fragments on purpose: a contiguous
// provider token literal in a committed file trips github push-protection (and
// every other secret scanner) even though it's a test fixture. splitting it
// keeps the literal out of source while ScanSecrets still sees the joined value.
const (
	fakeAWSKey    = "AKIA" + "IOSFODNN7EXAMPLE"
	fakeAWSSecret = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
	fakeGitHub    = "ghp_" + "aB3dEfGh1jKlMn0pQrStUvWxYz012345abcd"
	fakeSlack     = "xoxb-" + "123456789012-abcdefABCDEF1234567890ab"
	fakeStripe    = "sk_live_" + "0000000000000000000000"
	fakeGoogle    = "AIza" + "SyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"
	fakeGeneric   = "x9Kq2Lm7Pz4Rt6Wv8Bn3Cd5Fg1Hj0As"
	fakePEM       = "-----BEGIN RSA PRIVATE " + "KEY-----\nMIIEpAIB..."
)

// fakes for the rebuilt rules; the derived ones end in a non-word char to
// exercise the dropped trailing word boundaries.
var (
	fakeStripeRestricted = "rk_live_" + "0000000000000000000000"
	fakeGitHubPAT        = "github_pat_" + strings.Repeat("a1B2c3D4", 10) + "ab"
	fakeSlackApp         = "xapp-1-" + "A01B23C45D6-1234567890-abcdefABCDEF"
	fakeEncryptedPEM     = "-----BEGIN ENCRYPTED PRIVATE " + "KEY-----\nMIIFDjBA..."
	fakeAWSSecretSlash   = fakeAWSSecret[:len(fakeAWSSecret)-1] + "/"
	fakeGoogleDash       = fakeGoogle[:len(fakeGoogle)-1] + "-"
)

func TestScanSecrets(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantRule string // rule expected on the first match, "" means no match
		wantNone bool
	}{
		{
			name:     "aws access key id",
			content:  fmt.Sprintf(`const k = %q;`, fakeAWSKey),
			wantRule: "aws access key id",
		},
		{
			name:     "github personal token",
			content:  fmt.Sprintf(`token: %q`, fakeGitHub),
			wantRule: "github token",
		},
		{
			name:     "slack bot token",
			content:  fmt.Sprintf(`slack=%q`, fakeSlack),
			wantRule: "slack token",
		},
		{
			name:     "stripe live secret key",
			content:  fmt.Sprintf(`var sk = %q;`, fakeStripe),
			wantRule: "stripe secret key",
		},
		{
			name:     "google api key",
			content:  fmt.Sprintf(`apiKey: %q`, fakeGoogle),
			wantRule: "google api key",
		},
		{
			name:     "pem private key header",
			content:  fakePEM,
			wantRule: "private key",
		},
		{
			name:     "generic high-entropy api key assignment",
			content:  fmt.Sprintf(`apikey = %q`, fakeGeneric),
			wantRule: "generic secret assignment",
		},
		{
			name:     "aws secret with entropy",
			content:  fmt.Sprintf(`aws_secret_access_key=%q`, fakeAWSSecret),
			wantRule: "aws secret access key",
		},
		{
			// low-entropy assignment is a placeholder, not a real secret.
			name:     "low entropy generic assignment not flagged",
			content:  `password = "aaaaaaaaaaaaaaaaaaaaaaaa"`,
			wantNone: true,
		},
		{
			// a repetitive placeholder is low-entropy and must not trip the gate.
			name:     "low entropy repeated pattern not flagged",
			content:  `token = "abababababababababababab"`,
			wantNone: true,
		},
		{
			name:     "stripe restricted live key",
			content:  fmt.Sprintf(`var rk = %q;`, fakeStripeRestricted),
			wantRule: "stripe secret key",
		},
		{
			name:     "github fine-grained pat",
			content:  fmt.Sprintf(`pat: %q`, fakeGitHubPAT),
			wantRule: "github fine-grained pat",
		},
		{
			name:     "slack app-level token",
			content:  fmt.Sprintf(`slack=%q`, fakeSlackApp),
			wantRule: "slack token",
		},
		{
			name:     "encrypted pem private key header",
			content:  fakeEncryptedPEM,
			wantRule: "private key",
		},
		{
			// value ends in / so the old trailing \b dropped the match.
			name:     "aws secret ending in slash",
			content:  fmt.Sprintf(`aws_secret_access_key=%q`, fakeAWSSecretSlash),
			wantRule: "aws secret access key",
		},
		{
			// value ends in - so the old trailing \b dropped the match.
			name:     "google api key ending in dash",
			content:  fmt.Sprintf(`apiKey: %q`, fakeGoogleDash),
			wantRule: "google api key",
		},
		{
			// publishable pk_ keys are public by design, not a finding.
			name:     "stripe publishable key not flagged",
			content:  `pub = "pk_live_0000000000000000000000"`,
			wantNone: true,
		},
		{
			name:     "stripe test key not flagged",
			content:  `k = "sk_test_0000000000000000000000"`,
			wantNone: true,
		},
		{
			// the rk_live substring inside spark_live must not match (word boundary).
			name:     "spark_live substring not flagged",
			content:  `sparkCfg = "spark_live_aBcDeF1234567890XY"`,
			wantNone: true,
		},
		{
			name:     "digitless camelcase generic not flagged",
			content:  `token = "getUserAccountSettings"`,
			wantNone: true,
		},
		{
			name:     "no secrets in plain code",
			content:  `function add(a, b) { return a + b; }`,
			wantNone: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ScanSecrets(tt.content, "https://example.com/app.js")

			if tt.wantNone {
				if len(got) != 0 {
					t.Fatalf("expected no matches, got %+v", got)
				}
				return
			}

			if len(got) == 0 {
				t.Fatalf("expected a %q match, got none", tt.wantRule)
			}
			if got[0].Rule != tt.wantRule {
				t.Errorf("rule = %q, want %q", got[0].Rule, tt.wantRule)
			}
			if got[0].Match == "" {
				t.Error("match value is empty")
			}
			if got[0].Source != "https://example.com/app.js" {
				t.Errorf("source = %q, want the passed url", got[0].Source)
			}
		})
	}
}

func TestScanSecretsDedupesWithinSource(t *testing.T) {
	// the same key referenced twice in one file is one finding.
	content := fmt.Sprintf(`a = %q; b = %q;`, fakeAWSKey, fakeAWSKey)
	got := ScanSecrets(content, "https://example.com/app.js")
	if len(got) != 1 {
		t.Fatalf("expected 1 deduped match, got %d: %+v", len(got), got)
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name  string
		input string
		// random-ish strings clear the generic gate, repetitive ones don't.
		wantHigh bool
	}{
		{name: "empty is zero", input: "", wantHigh: false},
		{name: "repeated char is low", input: "aaaaaaaaaaaaaaaa", wantHigh: false},
		{name: "random blob is high", input: fakeGeneric, wantHigh: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannonEntropy(tt.input)
			if tt.wantHigh && got < genericMinEntropy {
				t.Errorf("entropy %f below generic gate %f", got, genericMinEntropy)
			}
			if !tt.wantHigh && got >= genericMinEntropy {
				t.Errorf("entropy %f unexpectedly cleared generic gate %f", got, genericMinEntropy)
			}
		})
	}
}
