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
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/httpx"
)

func TestExtractPotentialBuckets(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		want   []string // candidates that must be generated
		absent []string // candidates that must not be generated
	}{
		{
			name:   "strips the tld and pairs labels both ways",
			host:   "shop.example.com",
			want:   []string{"shop", "shop-s3", "s3-shop", "example", "shop-example", "example-shop"},
			absent: []string{"com", "com-s3", "s3-com", "example-com", "com-example"},
		},
		{
			name:   "combines non-adjacent labels",
			host:   "a.b.c.example.com",
			want:   []string{"a-c", "c-a", "a-example", "example-a", "b-example"},
			absent: []string{"com", "example-com"},
		},
		{
			name:   "single-label host keeps its only label and makes no pairs",
			host:   "localhost",
			want:   []string{"localhost", "localhost-s3", "s3-localhost"},
			absent: []string{"localhost-localhost", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPotentialBuckets(tt.host)
			for _, w := range tt.want {
				if !slices.Contains(got, w) {
					t.Errorf("extractPotentialBuckets(%q) missing %q; got %v", tt.host, w, got)
				}
			}
			for _, a := range tt.absent {
				if slices.Contains(got, a) {
					t.Errorf("extractPotentialBuckets(%q) should not generate %q; got %v", tt.host, a, got)
				}
			}
		})
	}
}

// TestCheckS3Bucket_StatusOKAlone proves the false positive this fix closes:
// a 200 response whose body is an AccessDenied error (or an unrelated
// landing page) must not be reported as an anonymously listable bucket, even
// though the bare status code says 200. against the pre-fix code (status
// only) every one of these would have wrongly returned true.
func TestCheckS3Bucket_StatusOKAlone(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		want       bool
	}{
		{
			name:       "200 with AccessDenied body is not a listing",
			statusCode: http.StatusOK,
			body: `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`,
			want: false,
		},
		{
			name:       "200 with unrelated landing page is not a listing",
			statusCode: http.StatusOK,
			body:       `<html><body><h1>Welcome to example corp</h1></body></html>`,
			want:       false,
		},
		{
			name:       "200 with empty body is not a listing",
			statusCode: http.StatusOK,
			body:       ``,
			want:       false,
		},
		{
			name:       "403 AccessDenied is not a listing",
			statusCode: http.StatusForbidden,
			body: `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`,
			want: false,
		},
		{
			name:       "200 with a real ListBucketResult is a listing",
			statusCode: http.StatusOK,
			body: `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Name>example-bucket</Name><Contents><Key>secret.txt</Key></Contents>
</ListBucketResult>`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			orig := s3EndpointFmt
			s3EndpointFmt = srv.URL + "/%s"
			defer func() { s3EndpointFmt = orig }()

			client := httpx.Client(5 * time.Second)
			got, err := checkS3Bucket(context.Background(), "some-bucket", client)
			if err != nil {
				t.Fatalf("checkS3Bucket() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("checkS3Bucket() = %v, want %v (status=%d body=%q)", got, tt.want, tt.statusCode, tt.body)
			}
		})
	}
}

func TestIsListableBucketBody(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "real listing",
			body: `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name></ListBucketResult>`,
			want: true,
		},
		{
			name: "access denied even if listing marker somehow present",
			body: `<ListBucketResult><Name>b</Name></ListBucketResult><Error><Code>AccessDenied</Code></Error>`,
			want: false,
		},
		{name: "no marker at all", body: `<html>nothing here</html>`, want: false},
		{name: "empty body", body: ``, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isListableBucketBody([]byte(tt.body)); got != tt.want {
				t.Errorf("isListableBucketBody(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}
