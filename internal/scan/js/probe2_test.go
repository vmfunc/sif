package js

import (
	"testing"
	"time"
)

func TestProbe_NoPanicOnBinary(t *testing.T) {
	inputs := [][]byte{
		{}, {0x00}, {0xff, 0xfe, 0xfd},
		[]byte("ey."), []byte(`"ey.a"`), []byte(`"eyJ.a.b"`),
		[]byte("\xff\xfe invalid utf8 \x80\x81 token=\"x\""),
		[]byte(`"//"`), []byte(`"/"`), []byte(`"./"`),
	}
	// binary with an embedded jwt-ish token to reach the decode path
	inputs = append(inputs, []byte(`x="ey`+"\xff\xff"+`.aa.bb"`))
	for _, in := range inputs {
		s := string(in)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic on %q: %v", s, r)
				}
			}()
			_ = ExtractEndpoints(s, "https://example.com/a.js")
			_ = ScanSecrets(s, "https://example.com/a.js")
			_, _ = ScanSupabase(s, "https://example.com/a.js", time.Second)
		}()
	}
	t.Log("no panics across binary/truncated/multibyte/empty inputs")
}

// regression: the 7 quoted regex-flag literals must never be reported as
// endpoints, but short real endpoints in the same shape (/xx or /xxx) must
// still extract normally.
func TestRegexFlagEndpointsNotReported(t *testing.T) {
	fps := []string{"/gi", "/gm", "/gs", "/gu", "/gy", "/mi", "/su"}
	for _, f := range fps {
		got := ExtractEndpoints(`x.replace("`+f+`","")`, "https://ex.com/a.js")
		if len(got) > 0 {
			t.Errorf("regex-flag literal %q wrongly reported as endpoint: %v", f, got)
		}
	}
}

func TestShortRealEndpointsStillExtracted(t *testing.T) {
	cases := []struct {
		content string
		want    string
	}{
		{`fetch("/v1")`, "https://ex.com/v1"},
		{`fetch("/me")`, "https://ex.com/me"},
		{`fetch("/ws")`, "https://ex.com/ws"},
		{`fetch("/db")`, "https://ex.com/db"},
	}
	for _, c := range cases {
		got := ExtractEndpoints(c.content, "https://ex.com/a.js")
		found := false
		for _, e := range got {
			if e == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %q preserved as an endpoint, got %v", c.want, got)
		}
	}
}
