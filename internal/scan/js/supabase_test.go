package js

import (
	"encoding/base64"
	"testing"
)

func TestParseSupabaseJwtBody(t *testing.T) {
	// claims segment whose base64url encoding contains both - and _; decodes to
	// {"ref":"|Z7>2V[qx?fw0","role":"anon"}. RawStdEncoding rejects it outright.
	urlSafeSeg := "eyJyZWYiOiJ8Wjc-MlZbcXg_ZncwIiwicm9sZSI6ImFub24ifQ"

	stdJSON := []byte(`{"ref":"mjrnzxqptwubhklsdvca","role":"anon"}`)
	rawSeg := base64.RawURLEncoding.EncodeToString(stdJSON)
	paddedSeg := base64.URLEncoding.EncodeToString(stdJSON)

	// json null unmarshals into a nil pointer without error; the decoder must
	// surface it as an error so ScanSupabase does not nil-deref the result.
	nullSeg := base64.RawURLEncoding.EncodeToString([]byte("null"))
	// valid claims without ref/role must decode cleanly with nil fields.
	noClaimsSeg := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"supabase"}`))

	cases := []struct {
		name    string
		token   string
		wantErr bool
		wantRef string // only checked when the case sets a non-empty value
	}{
		{"url-safe payload", "hdr." + urlSafeSeg + ".sig", false, "|Z7>2V[qx?fw0"},
		{"unpadded base64url", "hdr." + rawSeg + ".sig", false, "mjrnzxqptwubhklsdvca"},
		{"padded base64url", "hdr." + paddedSeg + ".sig", false, "mjrnzxqptwubhklsdvca"},
		{"too few segments", "hdr.sig", true, ""},
		{"invalid base64", "hdr.!!!!.sig", true, ""},
		{"json null body", "hdr." + nullSeg + ".sig", true, ""},
		{"no ref or role", "hdr." + noClaimsSeg + ".sig", false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := parseSupabaseJwtBody(tc.token)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseSupabaseJwtBody(%q) = nil err, want error", tc.token)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSupabaseJwtBody(%q) error: %v", tc.token, err)
			}
			// a valid decode must never yield a nil body; callers dereference it.
			if body == nil {
				t.Fatalf("parseSupabaseJwtBody(%q) = nil body, nil err", tc.token)
			}
			if tc.wantRef == "" {
				return
			}
			if body.ProjectId == nil || *body.ProjectId != tc.wantRef {
				t.Fatalf("ProjectId = %v, want %q", body.ProjectId, tc.wantRef)
			}
		})
	}
}
