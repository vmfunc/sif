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
	"math"
	"regexp"
	"strings"
)

// SecretMatch is one credential the scanner pulled out of a script.
type SecretMatch struct {
	Rule   string `json:"rule"`
	Match  string `json:"match"`
	Source string `json:"source"`
}

// entropy thresholds gate the noisy generic rules: provider-prefixed keys are
// trustworthy on their own, but a bare apikey="..." or a loose token blob is
// only worth reporting once its shannon entropy clears the bar for "this looks
// random, not an english word". secrets sit higher than the pem/aws-secret bar
// because the generic capture groups also catch ordinary identifiers.
const (
	genericMinEntropy   = 3.5
	awsSecretMinEntropy = 3.0
	// rules with no entropy requirement (prefix is already unique enough).
	noEntropyGate = 0.0
)

// secretRules is the credential regex bank. the matching group (or the whole
// match when there's no group) is what gets reported; minEntropy gates the
// generic high-entropy rules so we don't flag every short literal.
var secretRules = []struct {
	name         string
	re           *regexp.Regexp
	minEntropy   float64
	requireDigit bool
}{
	{
		// aws access key ids are fixed-shape and unmistakable.
		name:       "aws access key id",
		re:         regexp.MustCompile(`\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b`),
		minEntropy: noEntropyGate,
	},
	{
		// aws secret keys are 40-char base64-ish blobs; gate on entropy since the
		// shape alone matches plenty of innocent strings.
		// no trailing \b: keys ending in / or + have no word boundary there.
		name:       "aws secret access key",
		re:         regexp.MustCompile(`\b((?:aws_secret_access_key|aws_secret|secret_key)["']?\s*[:=]\s*["']?)([A-Za-z0-9/+]{40})`),
		minEntropy: awsSecretMinEntropy,
	},
	{
		// github personal/oauth/server/refresh/app tokens share the ghX_ prefix.
		name:       "github token",
		re:         regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,255})\b`),
		minEntropy: noEntropyGate,
	},
	{
		name:       "github fine-grained pat",
		re:         regexp.MustCompile(`\b(github_pat_[0-9A-Za-z_]{82})\b`),
		minEntropy: noEntropyGate,
	},
	{
		// slack bot/user/app/legacy tokens, plus xapp tokens.
		name:       "slack token",
		re:         regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z-]{10,}|xapp-[0-9]+-[0-9A-Za-z-]{10,})\b`),
		minEntropy: noEntropyGate,
	},
	{
		// stripe live secret and restricted keys; publishable pk_ keys are public
		// by design and test keys are not findings.
		name:       "stripe secret key",
		re:         regexp.MustCompile(`\b((?:sk|rk)_live_[0-9A-Za-z]{16,})\b`),
		minEntropy: noEntropyGate,
	},
	{
		// google api keys are a fixed AIza-prefixed 39-char shape; same
		// trailing-\b issue as above (dash-ending keys).
		name:       "google api key",
		re:         regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})`),
		minEntropy: noEntropyGate,
	},
	{
		// pem private key blocks; the header alone is the smoking gun.
		name:       "private key",
		re:         regexp.MustCompile(`-{5}BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-{5}`),
		minEntropy: noEntropyGate,
	},
	{
		// gitlab personal access tokens; the glpat- prefix is unmistakable and
		// covers both the classic 20-char and longer routable tokens.
		name:       "gitlab personal access token",
		re:         regexp.MustCompile(`\b(glpat-[0-9A-Za-z_-]{20,})\b`),
		minEntropy: noEntropyGate,
	},
	{
		// anthropic api and admin keys end in a fixed AA pad after 93 chars.
		name:       "anthropic api key",
		re:         regexp.MustCompile(`\b(sk-ant-(?:api03|admin01)-[0-9A-Za-z_-]{93}AA)\b`),
		minEntropy: noEntropyGate,
	},
	{
		name:       "npm access token",
		re:         regexp.MustCompile(`\b(npm_[0-9A-Za-z]{36})\b`),
		minEntropy: noEntropyGate,
	},
	{
		name:       "google oauth client secret",
		re:         regexp.MustCompile(`\b(GOCSPX-[0-9A-Za-z_-]{28})\b`),
		minEntropy: noEntropyGate,
	},
	{
		name:       "stripe webhook secret",
		re:         regexp.MustCompile(`\b(whsec_[0-9A-Za-z]{32,})\b`),
		minEntropy: noEntropyGate,
	},
	{
		// shopify admin/shared/private/custom app tokens, 32 hex after the prefix.
		name:       "shopify access token",
		re:         regexp.MustCompile(`\b(shp(?:at|ss|pa|ca)_[0-9a-fA-F]{32})\b`),
		minEntropy: noEntropyGate,
	},
	{
		name:       "sendgrid api key",
		re:         regexp.MustCompile(`\b(SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43})\b`),
		minEntropy: noEntropyGate,
	},
	{
		// slack incoming-webhook urls embed the secret in the path.
		name:       "slack webhook url",
		re:         regexp.MustCompile(`\b(hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z]{24})\b`),
		minEntropy: noEntropyGate,
	},
	{
		// generic apikey/secret/token = "<value>" assignments; the value is in
		// group 2 and only reported if it looks random (entropy gate) and carries
		// a digit, which weeds out camelCase identifiers sitting just over the gate.
		name:         "generic secret assignment",
		re:           regexp.MustCompile(`(?i)\b(api[_-]?key|secret|token|password|passwd|auth)["']?\s*[:=]\s*["']([0-9A-Za-z\-._~+/]{16,})["']`),
		minEntropy:   genericMinEntropy,
		requireDigit: true,
	},
}

// the value capture group lives at index 2 for the rules that prefix the
// keyword; index 0 (whole match) is used otherwise.
const (
	valueGroupIndex = 2
	wholeMatchIndex = 0
)

// ScanSecrets runs the regex bank over a script body and returns every gated
// match, deduped within this one source. srcURL is recorded on each find.
func ScanSecrets(content, srcURL string) []SecretMatch {
	matches := make([]SecretMatch, 0)
	seen := make(map[string]struct{})

	for i := 0; i < len(secretRules); i++ {
		rule := secretRules[i]
		groups := rule.re.FindAllStringSubmatch(content, -1)
		for j := 0; j < len(groups); j++ {
			value := secretValue(groups[j])
			if value == "" {
				continue
			}

			// entropy gate weeds out english-y identifiers for the generic rules;
			// prefixed rules pass with a zero threshold.
			if rule.minEntropy > noEntropyGate && shannonEntropy(value) < rule.minEntropy {
				continue
			}

			if rule.requireDigit && !hasDigit(value) {
				continue
			}

			// dedupe per source so a key referenced twice is one finding.
			key := rule.name + "\x00" + value
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			matches = append(matches, SecretMatch{Rule: rule.name, Match: value, Source: srcURL})
		}
	}

	return matches
}

// secretValue returns the reported portion of a regex match: the dedicated
// value group when the rule captures one, otherwise the whole match.
func secretValue(groups []string) string {
	if len(groups) > valueGroupIndex && groups[valueGroupIndex] != "" {
		return groups[valueGroupIndex]
	}
	return strings.TrimSpace(groups[wholeMatchIndex])
}

func hasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			return true
		}
	}
	return false
}

// shannonEntropy is the per-character shannon entropy (bits) of s, used to tell
// random-looking secrets apart from plain words. empty input is zero entropy.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}

	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}

	length := float64(len([]rune(s)))
	var entropy float64
	for _, count := range counts {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}
