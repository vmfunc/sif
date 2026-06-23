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

package scan

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
)

// JWTResult collects every token discovered on the target plus the offline
// analysis of each one.
type JWTResult struct {
	Tokens []JWTToken `json:"tokens,omitempty"`
}

// JWTToken is one decoded jwt and the weaknesses found in it. Token is trimmed
// to a short prefix so we never log a full credential.
type JWTToken struct {
	Source  string         `json:"source"`   // where we found it (header name / cookie / body)
	Preview string         `json:"preview"`  // first chars of the raw token, never the whole thing
	Alg     string         `json:"alg"`      // header alg claim
	Issues  []JWTIssue     `json:"issues"`   // the weaknesses, ranked
	Claims  map[string]any `json:"claims"`   // decoded payload (for reporting)
	WeakKey string         `json:"weak_key"` // cracked hmac secret, empty when none
}

// JWTIssue is a single weakness with a severity so the report layer can rank it.
type JWTIssue struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

// jwtBodyReadCap bounds how much of the response body we slurp looking for
// tokens; a jwt riding in the body is near the top, so a megabyte is plenty
// without letting a huge response exhaust memory.
const jwtBodyReadCap = 1 << 20

// jwtPreviewLen is how many leading characters of a token we keep for evidence.
// enough to identify the token in a report, short enough to never be the whole
// credential.
const jwtPreviewLen = 16

// the three structural jwt severities.
const (
	jwtSevCritical = "critical"
	jwtSevHigh     = "high"
	jwtSevMedium   = "medium"
	jwtSevLow      = "low"
)

// jwtRegex matches a compact-serialization jwt: three base64url segments split
// by dots. the header always starts "eyJ" (base64url of `{"`), which anchors the
// match and keeps it from firing on arbitrary dotted tokens.
var jwtRegex = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

// jwtWeakSecrets is a tiny offline wordlist of hmac secrets seen in tutorials,
// boilerplate and leaked configs. cracking one means anyone can forge tokens, so
// a hit is critical. kept short on purpose - this is a smoke test, not john.
var jwtWeakSecrets = []string{
	"secret", "secretkey", "secret_key", "your-256-bit-secret",
	"changeme", "password", "jwt", "jwtsecret", "key", "test",
	"admin", "supersecret", "s3cr3t", "qwerty", "123456",
}

// sensitiveClaimKeys are payload fields that should never travel in a readable
// jwt body (the payload is only base64, not encrypted). a match is a disclosure.
var sensitiveClaimKeys = []string{
	"password", "passwd", "secret", "api_key", "apikey", "ssn",
	"credit_card", "card_number", "private_key", "access_key",
}

// JWT fetches the target once, harvests every jwt from the response headers,
// cookies and body, then analyzes each one entirely offline.
func JWT(targetURL string, timeout time.Duration, logdir string) (*JWTResult, error) {
	log := output.Module("JWT")
	log.Start()

	sanitizedURL := stripScheme(targetURL)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "JWT discovery + offline analysis"); err != nil {
			log.Error("error creating log file: %v", err)
			return nil, fmt.Errorf("create jwt log: %w", err)
		}
	}

	client := httpx.Client(timeout)
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build jwt request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwt target: %w", err)
	}
	defer resp.Body.Close()

	// one read, capped; everything past this point is offline.
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwtBodyReadCap))
	if err != nil {
		return nil, fmt.Errorf("read jwt body: %w", err)
	}

	raws := harvestJWTs(resp, string(body))
	if len(raws) == 0 {
		log.Info("no jwts found on target")
		log.Complete(0, "found")
		return nil, nil //nolint:nilnil // absence of a token is not an error
	}

	result := &JWTResult{Tokens: make([]JWTToken, 0, len(raws))}
	for _, hit := range raws {
		token, ok := analyzeJWT(hit.source, hit.raw)
		if !ok {
			continue
		}
		result.Tokens = append(result.Tokens, token)

		for i := 0; i < len(token.Issues); i++ {
			iss := token.Issues[i]
			log.Warn("jwt %s: %s (%s)", renderJWTSeverity(iss.Severity), iss.Kind, hit.source)
			if logdir != "" {
				_ = logger.Write(sanitizedURL, logdir,
					fmt.Sprintf("JWT %s: %s - %s [%s]\n", iss.Severity, iss.Kind, iss.Detail, hit.source))
			}
		}
	}

	if len(result.Tokens) == 0 {
		log.Complete(0, "found")
		return nil, nil //nolint:nilnil // tokens were malformed, nothing to report
	}

	log.Complete(len(result.Tokens), "analyzed")
	return result, nil
}

// jwtHit ties a raw token to where it came from so the report can attribute it.
type jwtHit struct {
	source string
	raw    string
}

// harvestJWTs pulls every jwt out of the response: Authorization-style headers,
// Set-Cookie values and the body. dedup keys on the raw token so the same value
// echoed in two places is reported once.
func harvestJWTs(resp *http.Response, body string) []jwtHit {
	seen := make(map[string]struct{})
	var hits []jwtHit

	add := func(source, raw string) {
		if _, ok := seen[raw]; ok {
			return
		}
		seen[raw] = struct{}{}
		hits = append(hits, jwtHit{source: source, raw: raw})
	}

	for name, values := range resp.Header {
		for i := 0; i < len(values); i++ {
			for _, m := range jwtRegex.FindAllString(values[i], -1) {
				add("header:"+name, m)
			}
		}
	}
	for _, c := range resp.Cookies() {
		for _, m := range jwtRegex.FindAllString(c.Value, -1) {
			add("cookie:"+c.Name, m)
		}
	}
	for _, m := range jwtRegex.FindAllString(body, -1) {
		add("body", m)
	}

	return hits
}

// analyzeJWT decodes the header and payload (offline base64url, never verifying a
// signature against the network) and runs every weakness check. ok is false when
// the token doesn't decode into a real header+payload, so junk that matched the
// regex is dropped rather than reported.
func analyzeJWT(source, raw string) (JWTToken, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return JWTToken{}, false
	}

	header, err := decodeJWTSegment(parts[0])
	if err != nil {
		return JWTToken{}, false
	}
	payload, err := decodeJWTSegment(parts[1])
	if err != nil {
		return JWTToken{}, false
	}

	alg, _ := header["alg"].(string)

	token := JWTToken{
		Source:  source,
		Preview: previewToken(raw),
		Alg:     alg,
		Claims:  payload,
	}

	token.Issues = append(token.Issues, jwtAlgIssues(alg)...)
	token.Issues = append(token.Issues, jwtClaimIssues(payload)...)

	// only bother cracking when the alg is actually hmac; an asymmetric token
	// has no shared secret to guess.
	if isHMACAlg(alg) {
		if secret, ok := crackHMAC(raw, alg); ok {
			token.WeakKey = secret
			token.Issues = append(token.Issues, JWTIssue{
				Kind:     "weak hmac secret",
				Severity: jwtSevCritical,
				Detail:   "signature verifies against bundled weak secret " + secret,
			})
		}
	}

	return token, true
}

// jwtAlgIssues flags the algorithm-level weaknesses: alg:none (no signature at
// all) and the RS256->HS256 confusion surface (an asymmetric-looking token whose
// header says HS*, meaning a server that loads the public key as an hmac secret
// can be forged).
func jwtAlgIssues(alg string) []JWTIssue {
	var issues []JWTIssue
	lower := strings.ToLower(alg)

	if lower == "none" || alg == "" {
		issues = append(issues, JWTIssue{
			Kind:     "alg:none",
			Severity: jwtSevCritical,
			Detail:   "token declares no signature algorithm; forgeable",
		})
		return issues
	}

	if isHMACAlg(alg) {
		issues = append(issues, JWTIssue{
			Kind:     "rs256->hs256 confusion surface",
			Severity: jwtSevMedium,
			Detail: "token is HMAC-signed; if the server also accepts asymmetric algs " +
				"with the same verifier, a public key can be used as the HMAC secret",
		})
	}
	return issues
}

// jwtClaimIssues inspects the decoded payload for missing/expired expiry and any
// plaintext sensitive claims (the payload is base64, not encrypted).
func jwtClaimIssues(payload map[string]any) []JWTIssue {
	var issues []JWTIssue

	exp, hasExp := numericClaim(payload, "exp")
	switch {
	case !hasExp:
		issues = append(issues, JWTIssue{
			Kind:     "missing exp",
			Severity: jwtSevMedium,
			Detail:   "no expiry claim; token never ages out",
		})
	case time.Now().After(time.Unix(int64(exp), 0)):
		issues = append(issues, JWTIssue{
			Kind:     "expired token",
			Severity: jwtSevLow,
			Detail:   "exp is in the past; a server still honoring it is a bug",
		})
	}

	for i := 0; i < len(sensitiveClaimKeys); i++ {
		key := sensitiveClaimKeys[i]
		if _, ok := payload[key]; ok {
			issues = append(issues, JWTIssue{
				Kind:     "sensitive plaintext claim",
				Severity: jwtSevHigh,
				Detail:   "payload carries readable claim " + key + "; jwt bodies are not encrypted",
			})
		}
	}

	return issues
}

// crackHMAC tries every bundled weak secret against the token's signature offline,
// using the hash that matches alg (HS256/HS384/HS512). a verifying secret means the
// token is forgeable; the wordlist catches lazy defaults, it is not a real cracker.
func crackHMAC(raw, alg string) (string, bool) {
	newHash, ok := hmacHash(alg)
	if !ok {
		return "", false
	}

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", false
	}
	signingInput := parts[0] + "." + parts[1]
	want, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", false
	}

	for i := 0; i < len(jwtWeakSecrets); i++ {
		secret := jwtWeakSecrets[i]
		mac := hmac.New(newHash, []byte(secret))
		mac.Write([]byte(signingInput))
		if hmac.Equal(mac.Sum(nil), want) {
			return secret, true
		}
	}
	return "", false
}

// hmacHash maps an HMAC jwt alg to its hash constructor; ok is false for any
// non-HMAC or unknown alg. it is stricter than isHMACAlg: the confusion-surface
// finding fires on any HS* alg, but cracking needs a computable digest width.
func hmacHash(alg string) (func() hash.Hash, bool) {
	switch strings.ToUpper(alg) {
	case "HS256":
		return sha256.New, true
	case "HS384":
		return sha512.New384, true
	case "HS512":
		return sha512.New, true
	default:
		return nil, false
	}
}

// decodeJWTSegment base64url-decodes one jwt segment into a claims map. jwt uses
// unpadded base64url, but some emitters pad anyway, so try raw first then padded.
func decodeJWTSegment(seg string) (map[string]any, error) {
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(seg)
		if err != nil {
			return nil, fmt.Errorf("base64url decode segment: %w", err)
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal jwt segment: %w", err)
	}
	return claims, nil
}

// numericClaim pulls a numeric claim out of the payload. json numbers decode to
// float64, so that's the only shape we accept.
func numericClaim(payload map[string]any, key string) (float64, bool) {
	v, ok := payload[key]
	if !ok {
		return 0, false
	}
	f, ok := v.(float64)
	return f, ok
}

// isHMACAlg reports whether alg is one of the HMAC family (HS256/HS384/HS512).
func isHMACAlg(alg string) bool {
	return strings.HasPrefix(strings.ToUpper(alg), "HS")
}

// previewToken trims a raw token to a short prefix so evidence never carries the
// whole credential.
func previewToken(raw string) string {
	if len(raw) <= jwtPreviewLen {
		return raw
	}
	return raw[:jwtPreviewLen] + "..."
}

func renderJWTSeverity(severity string) string {
	switch severity {
	case jwtSevCritical:
		return output.SeverityCritical.Render(severity)
	case jwtSevHigh:
		return output.SeverityHigh.Render(severity)
	case jwtSevMedium:
		return output.SeverityMedium.Render(severity)
	default:
		return output.SeverityLow.Render(severity)
	}
}

// ResultType identifies jwt findings for the result registry.
func (r *JWTResult) ResultType() string { return "jwt" }

var _ ScanResult = (*JWTResult)(nil)
