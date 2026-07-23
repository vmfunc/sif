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
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
	"github.com/vmfunc/sif/internal/styles"
)

// maxBucketBodyReadBytes bounds how much of a bucket response we buffer to
// look for the listing markers below. an XML/JSON listing root or an error
// code always shows up well within this window; the rest is drained and
// discarded by httpx.DrainClose.
const maxBucketBodyReadBytes = 8 << 10

// s3ListingMarker is the root element of a real S3 ListBucketResult XML
// listing. its presence is what actually proves anonymous listing access;
// AccessDenied/NoSuchBucket/redirect bodies also come back with status 200
// and must not be mistaken for a listing.
const s3ListingMarker = "<ListBucketResult"

// s3DeniedMarkers are S3 error codes that can accompany a 200 (or that we
// check regardless of status) and rule out a listing even if the listing
// marker were somehow also present.
var s3DeniedMarkers = []string{"AccessDenied", "NoSuchBucket", "PermanentRedirect", "AllAccessDisabled"}

// s3EndpointFmt is a var so integration tests can repoint it at a fixture; the
// %s is the bucket name.
var s3EndpointFmt = "https://%s.s3.amazonaws.com"

type CloudStorageResult struct {
	BucketName string `json:"bucket_name"`
	// IsPublic means the bucket's listing was actually retrieved (the
	// response body contains a ListBucketResult with no denial marker), not
	// merely that the request returned 200.
	IsPublic bool `json:"is_public"`
}

func CloudStorage(url string, timeout time.Duration, logdir string) ([]CloudStorageResult, error) {
	output.ScanStart("Cloud Storage Misconfiguration Scan")

	sanitizedURL := stripScheme(url)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "Cloud Storage Misconfiguration Scan"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return nil, err
		}
	}

	cloudlog := log.NewWithOptions(output.Writer(), log.Options{
		Prefix: "C3",
	}).With("url", url)

	client := httpx.Client(timeout)

	potentialBuckets := extractPotentialBuckets(sanitizedURL)

	var results []CloudStorageResult

	for _, bucket := range potentialBuckets {
		isPublic, err := checkS3Bucket(context.TODO(), bucket, client)
		if err != nil {
			cloudlog.Errorf("Error checking S3 bucket %s: %v", bucket, err)
			continue
		}

		result := CloudStorageResult{
			BucketName: bucket,
			IsPublic:   isPublic,
		}
		results = append(results, result)

		if isPublic {
			cloudlog.Warnf("Public S3 bucket found: %s", styles.Highlight.Render(bucket))
			if logdir != "" {
				_ = logger.Write(sanitizedURL, logdir, fmt.Sprintf("Public S3 bucket found: %s\n", bucket))
			}
		} else {
			cloudlog.Infof("S3 bucket is not public/found: %s", bucket)
		}
	}

	return results, nil
}

func extractPotentialBuckets(url string) []string {
	labels := strings.Split(url, ".")
	// drop the tld label so we don't waste guesses on it ("com", "com-s3", ...);
	// a single-label host has no tld to strip.
	if len(labels) > 1 {
		labels = labels[:len(labels)-1]
	}

	var buckets []string
	for _, label := range labels {
		buckets = append(buckets, label, label+"-s3", "s3-"+label)
	}
	// combine every label with every other, not just adjacent ones, so a deep
	// host like shop.cdn.example yields shop-example too.
	for i, a := range labels {
		for _, b := range labels[i+1:] {
			buckets = append(buckets, a+"-"+b, b+"-"+a)
		}
	}
	return buckets
}

func checkS3Bucket(ctx context.Context, bucket string, client *http.Client) (bool, error) {
	url := fmt.Sprintf(s3EndpointFmt, bucket)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req) //nolint:bodyclose // drained and closed via httpx.DrainClose
	if err != nil {
		return false, err
	}
	// any remainder past maxBucketBodyReadBytes is drained on close so the
	// conn returns to the pool.
	defer httpx.DrainClose(resp)

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBucketBodyReadBytes))
	if err != nil {
		return false, err
	}

	return isListableBucketBody(body), nil
}

// isListableBucketBody reports whether body proves an S3 bucket is
// anonymously listable. a 200 status alone does not: AccessDenied pages,
// provider landing pages, and locked buckets can all return 200, so the
// listing root element must actually be present and no denial marker may
// be present alongside it.
func isListableBucketBody(body []byte) bool {
	s := string(body)
	if !strings.Contains(s, s3ListingMarker) {
		return false
	}
	for _, marker := range s3DeniedMarkers {
		if strings.Contains(s, marker) {
			return false
		}
	}
	return true
}
