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
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/httpx"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/styles"
)

// s3EndpointFmt is a var so integration tests can repoint it at a fixture; the
// %s is the bucket name.
var s3EndpointFmt = "https://%s.s3.amazonaws.com"

type CloudStorageResult struct {
	BucketName string `json:"bucket_name"`
	IsPublic   bool   `json:"is_public"`
}

func CloudStorage(url string, timeout time.Duration, logdir string) ([]CloudStorageResult, error) {
	fmt.Println(styles.Separator.Render("Starting " + styles.Status.Render("Cloud Storage Misconfiguration Scan") + "..."))

	sanitizedURL := stripScheme(url)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "Cloud Storage Misconfiguration Scan"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return nil, err
		}
	}

	cloudlog := log.NewWithOptions(os.Stderr, log.Options{
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
	// TODO: handle non-adjacent label combos and strip the tld
	parts := strings.Split(url, ".")
	var buckets []string
	for i, part := range parts {
		buckets = append(buckets, part, part+"-s3", "s3-"+part)

		if i < len(parts)-1 {
			domainExtension := part + "-" + parts[i+1]
			buckets = append(buckets, domainExtension, parts[i+1]+"-"+part)
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
	// status only; drain on close so the conn returns to the pool.
	defer httpx.DrainClose(resp)

	// If we can access the bucket listing, it's public
	return resp.StatusCode == http.StatusOK, nil
}
