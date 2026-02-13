/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (vmfunc), xyzeva,                        :
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
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/styles"
)

type CloudStorageResult struct {
	BucketName string `json:"bucket_name"`
	IsPublic   bool   `json:"is_public"`
}

func CloudStorage(url string, timeout time.Duration, logdir string) ([]CloudStorageResult, error) {
	fmt.Println(styles.Separator.Render("☁️ Starting " + styles.Status.Render("Cloud Storage Misconfiguration Scan") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "Cloud Storage Misconfiguration Scan"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return nil, err
		}
	}

	cloudlog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "C3 ☁️",
	}).With("url", url)

	client := &http.Client{
		Timeout: timeout,
	}

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
	// This is a simple implementation.
	// TODO: add more cases
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
	url := fmt.Sprintf("https://%s.s3.amazonaws.com", bucket)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// If we can access the bucket listing, it's public
	return resp.StatusCode == http.StatusOK, nil
}
