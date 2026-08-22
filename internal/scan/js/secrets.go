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
	"encoding/base64"
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
// generic high-entropy rules so we don't flag every short literal. validate
// runs after the gates for rules where shape alone isn't proof.
var secretRules = []struct {
	name         string
	re           *regexp.Regexp
	minEntropy   float64
	requireDigit bool
	validate     func(string) bool
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
		// pypi tokens all share the pypi-AgEIcHlwaS5vcmc prefix, the base64
		// encoding of a fixed macaroon header, so it's effectively unforgeable.
		name:       "pypi api token",
		re:         regexp.MustCompile(`\b(pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,})\b`),
		minEntropy: noEntropyGate,
	},
	{
		// legacy openai secret keys embed a fixed T3BlbkFJ marker (base64 for
		// "OpenAI") between two random halves.
		name:       "openai api key",
		re:         regexp.MustCompile(`\b(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b`),
		minEntropy: noEntropyGate,
	},
	{
		// current-generation project and service-account keys.
		name:       "openai project api key",
		re:         regexp.MustCompile(`\b(sk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,})\b`),
		minEntropy: noEntropyGate,
	},
	{
		name:       "square access token",
		re:         regexp.MustCompile(`\b(sq0atp-[0-9A-Za-z_-]{22}|sq0csp-[0-9A-Za-z_-]{43})\b`),
		minEntropy: noEntropyGate,
	},
	{
		// mailgun api keys, key- then a 32-char hex blob.
		name:       "mailgun api key",
		re:         regexp.MustCompile(`\b(key-[0-9a-f]{32})\b`),
		minEntropy: noEntropyGate,
	},
	{
		// discord bot tokens: base64 user id, a timestamp segment, then an HMAC.
		name:       "discord bot token",
		re:         regexp.MustCompile(`\b([MNOP][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})\b`),
		minEntropy: noEntropyGate,
	},
	{
		// discord incoming-webhook urls embed the secret in the path.
		name:       "discord webhook url",
		re:         regexp.MustCompile(`\b(discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,68})`),
		minEntropy: noEntropyGate,
	},
	{
		name:       "new relic license key",
		re:         regexp.MustCompile(`\b(NRAK-[A-Z0-9]{27})\b`),
		minEntropy: noEntropyGate,
	},
	{
		// cloudinary connection urls carry the api key and secret in the userinfo.
		name:       "cloudinary url",
		re:         regexp.MustCompile(`\b(cloudinary://[0-9]{10,20}:[A-Za-z0-9_-]{20,}@[A-Za-z0-9_-]+)`),
		minEntropy: noEntropyGate,
	},
	{
		// jwts have no fixed prefix; validate decodes the header to rule out
		// arbitrary dotted base64url blobs.
		name:       "jwt",
		re:         regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`),
		minEntropy: noEntropyGate,
		validate:   isStructuredJWT,
	},
	{
		// validate drops the countless doc/template examples that use a
		// placeholder password.
		name:       "database connection string",
		re:         regexp.MustCompile(`\b((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|rediss|amqp|amqps)://[^:\s"'` + "`" + `/@]+:[^@\s"'` + "`" + `/]+@[^\s"'` + "`" + `]+)`),
		minEntropy: noEntropyGate,
		validate:   hasRealConnStringPassword,
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

			// structural validation for rules whose shape alone isn't proof.
			if rule.validate != nil && !rule.validate(value) {
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

// alg is mandatory per RFC 7519; requiring both fields keeps arbitrary
// dot-separated base64url blobs from being mistaken for a jwt.
const (
	jwtAlgField = `"alg"`
	jwtTypField = `"typ"`
)

// connStringPasswordRe pulls the userinfo password out of a scheme://user:pass@host
// connection string, for filtering placeholder credentials post-match.
var connStringPasswordRe = regexp.MustCompile(`://[^:@/\s]*:([^@/\s]+)@`)

// placeholderPasswords are stand-ins that show up constantly in docs, sample
// configs and .env.example files; matching one means the string isn't a real
// leaked credential.
var placeholderPasswords = map[string]struct{}{
	"password": {}, "pass": {}, "passwd": {}, "xxxx": {}, "xxxxx": {},
	"changeme": {}, "yourpassword": {}, "example": {}, "test": {},
	"123456": {}, "secret": {}, "admin": {}, "root": {}, "pwd": {},
}

// isStructuredJWT confirms the header segment decodes to jwt-shaped json.
func isStructuredJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}

	h := string(header)
	return strings.Contains(h, jwtAlgField) && strings.Contains(h, jwtTypField)
}

// hasRealConnStringPassword rejects known placeholder passwords.
func hasRealConnStringPassword(value string) bool {
	m := connStringPasswordRe.FindStringSubmatch(value)
	if len(m) < 2 {
		return true
	}

	_, placeholder := placeholderPasswords[strings.ToLower(m[1])]
	return !placeholder
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
