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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fixed jwt fixtures, generated offline. each exercises a distinct weakness.
const (
	// header {alg:none}, payload {sub:admin}, empty signature - forgeable.
	jwtNone = "eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0." +
		"eyJzdWIiOiAiYWRtaW4iLCAicm9sZSI6ICJ1c2VyIn0."

	// HS256, no exp claim, signed with the bundled weak secret "secret".
	jwtWeakHS256 = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9." +
		"eyJzdWIiOiAiMTIzNDU2Nzg5MCIsICJuYW1lIjogInRlc3RlciJ9." +
		"JOjVfLa8gp3cvFkNVgOnmdrI1MCHZRA_ChBmCPF-Z8w"

	// HS256, exp in 2001 (long past), signed with a secret not in the wordlist.
	jwtExpired = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9." +
		"eyJzdWIiOiAieCIsICJleHAiOiAxMDAwMDAwMDAwfQ." +
		"gr28Ffm4wJkonHGSKmMD5Rj7e1pTt2o_EwG6lMWQeSc"

	// HS256 carrying a plaintext password claim (jwt bodies are not encrypted).
	jwtSensitive = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9." +
		"eyJzdWIiOiAieCIsICJwYXNzd29yZCI6ICJodW50ZXIyIiwgImV4cCI6IDk5OTk5OTk5OTl9." +
		"rjEf0CUa7_qppuINi6zL9vupJIX0rzSBhul7kKM9uSA"

	// HS384, signed with the bundled weak secret "secret".
	jwtWeakHS384 = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InRlc3RlciJ9." +
		"OXNTuzKiGLxnpUjL24vvKlQzdOD-YKMinN8eu_v5luTXDUF65bHAQnz-M3VG2TVh"

	// HS512, signed with the bundled weak secret "secret".
	jwtWeakHS512 = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InRlc3RlciJ9." +
		"CXcZz0F9TTPg--B4WV1Vzty3gG_wcDG86H5QDSRe94MpcVXIcRTBK6H7OmqFyG4nNWYNXPOODCu426bgQMOzRQ"

	// HS384/HS512 signed with a strong secret absent from the wordlist; these
	// must never be cracked (no false positive on the wide-digest path).
	jwtStrongHS384 = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InRlc3RlciJ9." +
		"vHhjZPoXZnnZEvVYxX64J2wm8qWk-e6y_T20qTy_Su6sPmoUSMHS4tv6_D-hfwrY"
	jwtStrongHS512 = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6InRlc3RlciJ9." +
		"80ueFa0oI88ftySkn_MJ12GAd1r2cahXt_ICtCfWx58wJoAvEocbjBPC_efzOp8vm_39GlcCCDLeb6cFix3DBw"
)

// hasIssue reports whether the analyzed token carries an issue of the given kind.
func hasIssue(token *JWTToken, kind string) bool {
	for i := 0; i < len(token.Issues); i++ {
		if token.Issues[i].Kind == kind {
			return true
		}
	}
	return false
}

func TestJWT_AlgNoneAndMissingExpFlagged(t *testing.T) {
	// serve the alg:none token in the Authorization header echo.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Authorization", "Bearer "+jwtNone)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result, err := JWT(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("JWT: %v", err)
	}
	if result == nil || len(result.Tokens) != 1 {
		t.Fatalf("expected exactly one analyzed token, got %+v", result)
	}

	token := &result.Tokens[0]
	if !hasIssue(token, "alg:none") {
		t.Errorf("expected alg:none to be flagged, got issues %+v", token.Issues)
	}
	if !hasIssue(token, "missing exp") {
		t.Errorf("expected missing exp to be flagged, got issues %+v", token.Issues)
	}
	// the preview must never carry the whole token.
	if len(token.Preview) >= len(jwtNone) {
		t.Errorf("preview should be trimmed, got full token %q", token.Preview)
	}
}

func TestJWT_WeakSecretCracked(t *testing.T) {
	// token rides in a Set-Cookie this time.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: jwtWeakHS256})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	result, err := JWT(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("JWT: %v", err)
	}
	if result == nil || len(result.Tokens) != 1 {
		t.Fatalf("expected one token, got %+v", result)
	}

	token := &result.Tokens[0]
	if token.WeakKey != "secret" {
		t.Errorf("expected weak secret 'secret' to be cracked, got %q", token.WeakKey)
	}
	if !hasIssue(token, "weak hmac secret") {
		t.Errorf("expected weak hmac secret issue, got %+v", token.Issues)
	}
	if !hasIssue(token, "rs256->hs256 confusion surface") {
		t.Errorf("expected hmac confusion surface to be flagged, got %+v", token.Issues)
	}
}

func TestJWT_WeakSecretCrackedHS384HS512(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{
		{"HS384", jwtWeakHS384},
		{"HS512", jwtWeakHS512},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: tc.token})
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			result, err := JWT(srv.URL, 5*time.Second, "")
			if err != nil {
				t.Fatalf("JWT: %v", err)
			}
			if result == nil || len(result.Tokens) != 1 {
				t.Fatalf("expected one token, got %+v", result)
			}

			token := &result.Tokens[0]
			if token.WeakKey != "secret" {
				t.Errorf("expected weak secret 'secret' cracked on %s, got %q", tc.name, token.WeakKey)
			}
			if !hasIssue(token, "weak hmac secret") {
				t.Errorf("expected weak hmac secret issue on %s, got %+v", tc.name, token.Issues)
			}
		})
	}
}

func TestJWT_StrongSecretNotCrackedHS384HS512(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{
		{"HS384", jwtStrongHS384},
		{"HS512", jwtStrongHS512},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: tc.token})
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			result, err := JWT(srv.URL, 5*time.Second, "")
			if err != nil {
				t.Fatalf("JWT: %v", err)
			}
			if result == nil || len(result.Tokens) != 1 {
				t.Fatalf("expected one token, got %+v", result)
			}

			token := &result.Tokens[0]
			if token.WeakKey != "" {
				t.Errorf("strong-secret %s token must not be cracked, got %q", tc.name, token.WeakKey)
			}
			if hasIssue(token, "weak hmac secret") {
				t.Errorf("strong-secret %s token must not raise a weak-secret issue, got %+v", tc.name, token.Issues)
			}
		})
	}
}

func TestHMACHash(t *testing.T) {
	cases := []struct {
		alg      string
		wantOK   bool
		wantSize int // digest bytes when ok
	}{
		{"HS256", true, 32},
		{"HS384", true, 48},
		{"HS512", true, 64},
		{"hs256", true, 32}, // alg match is case-insensitive
		{"", false, 0},
		{"none", false, 0},
		{"RS256", false, 0},
		{"ES256", false, 0},
		{"HS1", false, 0},
		{"HS", false, 0},
	}
	for _, tc := range cases {
		newHash, ok := hmacHash(tc.alg)
		if ok != tc.wantOK {
			t.Errorf("hmacHash(%q) ok = %v, want %v", tc.alg, ok, tc.wantOK)
			continue
		}
		if ok && newHash().Size() != tc.wantSize {
			t.Errorf("hmacHash(%q) digest size = %d, want %d", tc.alg, newHash().Size(), tc.wantSize)
		}
	}
}

func TestCrackHMAC_RejectsMalformedAndNonHMAC(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		alg  string
	}{
		{"non-hmac alg", jwtWeakHS384, "RS256"},
		{"unknown hs alg", jwtWeakHS384, "HS1"},
		{"too few parts", "only.two", "HS256"},
		{"non-base64 signature", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.!!!notb64!!!", "HS256"},
	}
	for _, tc := range cases {
		if secret, ok := crackHMAC(tc.raw, tc.alg); ok || secret != "" {
			t.Errorf("%s: crackHMAC = (%q, %v), want (\"\", false)", tc.name, secret, ok)
		}
	}
}

func TestJWT_ExpiredFlagged(t *testing.T) {
	// token in the response body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token":"` + jwtExpired + `"}`))
	}))
	defer srv.Close()

	result, err := JWT(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("JWT: %v", err)
	}
	if result == nil || len(result.Tokens) != 1 {
		t.Fatalf("expected one token, got %+v", result)
	}
	if !hasIssue(&result.Tokens[0], "expired token") {
		t.Errorf("expected expired token to be flagged, got %+v", result.Tokens[0].Issues)
	}
	// a strong, unguessed secret must not be cracked.
	if result.Tokens[0].WeakKey != "" {
		t.Errorf("did not expect a cracked key on the strong-secret token, got %q", result.Tokens[0].WeakKey)
	}
}

func TestJWT_SensitiveClaimFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(jwtSensitive))
	}))
	defer srv.Close()

	result, err := JWT(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("JWT: %v", err)
	}
	if result == nil || len(result.Tokens) != 1 {
		t.Fatalf("expected one token, got %+v", result)
	}
	if !hasIssue(&result.Tokens[0], "sensitive plaintext claim") {
		t.Errorf("expected sensitive claim to be flagged, got %+v", result.Tokens[0].Issues)
	}
}

func TestJWT_NoTokens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("nothing to see here"))
	}))
	defer srv.Close()

	result, err := JWT(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatalf("JWT: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result when no tokens present, got %+v", result)
	}
}

func TestJWTResult_ResultType(t *testing.T) {
	r := &JWTResult{}
	if r.ResultType() != "jwt" {
		t.Errorf("expected result type 'jwt', got %q", r.ResultType())
	}
}
