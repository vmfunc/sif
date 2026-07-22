package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runBucketModule(t *testing.T, file string, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule(file)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	res, err := modules.ExecuteHTTPModule(context.Background(), srv.URL, def, modules.Options{
		Timeout: 5 * time.Second,
		Threads: 2,
	})
	if err != nil {
		t.Fatalf("execute %s: %v", file, err)
	}
	return res
}

func bucketExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestS3BucketListingExposureModule(t *testing.T) {
	const s3 = "../../modules/recon/s3-bucket-listing-exposure.yaml"

	t.Run("a real public bucket listing is flagged with the bucket and key", func(t *testing.T) {
		body := `<?xml version="1.0" encoding="UTF-8"?>` +
			`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
			`<Name>leaky-prod-backups</Name><Prefix></Prefix><Marker></Marker>` +
			`<MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>` +
			`<Contents><Key>db-dump-2026-06-01.sql.gz</Key><LastModified>2026-06-01T00:00:00.000Z</LastModified>` +
			`<ETag>"abc"</ETag><Size>10485760</Size><StorageClass>STANDARD</StorageClass></Contents>` +
			`</ListBucketResult>`
		res := runBucketModule(t, s3, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an s3 bucket listing finding")
		}
		if v := bucketExtract(res, "bucket_name"); v != "leaky-prod-backups" {
			t.Errorf("bucket_name=%q, want leaky-prod-backups", v)
		}
		if v := bucketExtract(res, "object_key"); v != "db-dump-2026-06-01.sql.gz" {
			t.Errorf("object_key=%q, want db-dump-2026-06-01.sql.gz", v)
		}
	})

	t.Run("an empty but public bucket still fires without needing contents", func(t *testing.T) {
		body := `<?xml version="1.0" encoding="UTF-8"?>` +
			`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
			`<Name>empty-public-bucket</Name><Prefix></Prefix><Marker></Marker>` +
			`<MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>`
		res := runBucketModule(t, s3, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an s3 bucket listing finding on an empty public bucket")
		}
	})

	t.Run("a locked bucket returning AccessDenied with 200 does not fire", func(t *testing.T) {
		body := `<?xml version="1.0" encoding="UTF-8"?>` +
			`<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`
		if res := runBucketModule(t, s3, 200, body); len(res.Findings) > 0 {
			t.Errorf("a 200 AccessDenied body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a locked bucket returning 403 AccessDenied does not fire", func(t *testing.T) {
		body := `<?xml version="1.0" encoding="UTF-8"?>` +
			`<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>`
		if res := runBucketModule(t, s3, 403, body); len(res.Findings) > 0 {
			t.Errorf("a 403 AccessDenied body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a gone bucket returning NoSuchBucket does not fire", func(t *testing.T) {
		body := `<?xml version="1.0" encoding="UTF-8"?>` +
			`<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>`
		if res := runBucketModule(t, s3, 404, body); len(res.Findings) > 0 {
			t.Errorf("a NoSuchBucket body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a normal html page does not fire", func(t *testing.T) {
		body := "<!DOCTYPE html><html><head><title>hi</title></head><body>hello</body></html>"
		if res := runBucketModule(t, s3, 200, body); len(res.Findings) > 0 {
			t.Errorf("a plain html page should not match, got %d findings", len(res.Findings))
		}
	})
}

func TestGCSBucketListingExposureModule(t *testing.T) {
	const gcs = "../../modules/recon/gcs-bucket-listing-exposure.yaml"

	t.Run("a real public gcs listing is flagged with the object name", func(t *testing.T) {
		body := `{"kind": "storage#objects", "items": [{"kind": "storage#object", "id": "leaky-gcs-bucket/report.csv/1",` +
			`"name": "report.csv", "bucket": "leaky-gcs-bucket", "size": "4096"}]}`
		res := runBucketModule(t, gcs, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a gcs bucket listing finding")
		}
		if v := bucketExtract(res, "object_name"); v != "report.csv" {
			t.Errorf("object_name=%q, want report.csv", v)
		}
	})

	t.Run("an empty but public bucket still fires without needing items", func(t *testing.T) {
		body := `{"kind": "storage#objects"}`
		res := runBucketModule(t, gcs, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected a gcs bucket listing finding on an empty public bucket")
		}
	})

	t.Run("a locked bucket returning a forbidden error does not fire", func(t *testing.T) {
		body := `{"error": {"errors": [{"domain": "global", "reason": "forbidden", "message": "does not have storage.objects.list access"}], "code": 403, "message": "forbidden"}}`
		if res := runBucketModule(t, gcs, 403, body); len(res.Findings) > 0 {
			t.Errorf("a forbidden error body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a missing bucket returning notFound does not fire", func(t *testing.T) {
		body := `{"error": {"errors": [{"domain": "global", "reason": "notFound", "message": "not found"}], "code": 404, "message": "not found"}}`
		if res := runBucketModule(t, gcs, 404, body); len(res.Findings) > 0 {
			t.Errorf("a notFound error body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a normal html page does not fire", func(t *testing.T) {
		body := "<!DOCTYPE html><html><head><title>hi</title></head><body>hello</body></html>"
		if res := runBucketModule(t, gcs, 200, body); len(res.Findings) > 0 {
			t.Errorf("a plain html page should not match, got %d findings", len(res.Findings))
		}
	})
}

func TestAzureBlobContainerListingExposureModule(t *testing.T) {
	const azure = "../../modules/recon/azure-blob-container-listing-exposure.yaml"

	t.Run("a real public container listing is flagged with the blob name", func(t *testing.T) {
		body := `<?xml version="1.0" encoding="utf-8"?>` +
			`<EnumerationResults ServiceEndpoint="https://leakyacct.blob.core.windows.net/" ContainerName="public">` +
			`<Blobs><Blob><Name>invoice-2026-06.pdf</Name><Properties><Content-Length>2048</Content-Length></Properties></Blob></Blobs>` +
			`<NextMarker/></EnumerationResults>`
		res := runBucketModule(t, azure, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an azure container listing finding")
		}
		if v := bucketExtract(res, "blob_name"); v != "invoice-2026-06.pdf" {
			t.Errorf("blob_name=%q, want invoice-2026-06.pdf", v)
		}
	})

	t.Run("an empty but public container still fires without needing blobs", func(t *testing.T) {
		body := `<?xml version="1.0" encoding="utf-8"?>` +
			`<EnumerationResults ServiceEndpoint="https://leakyacct.blob.core.windows.net/" ContainerName="empty">` +
			`<Blobs/><NextMarker/></EnumerationResults>`
		res := runBucketModule(t, azure, 200, body)
		if len(res.Findings) == 0 {
			t.Fatal("expected an azure container listing finding on an empty public container")
		}
	})

	t.Run("a locked container returning PublicAccessNotPermitted does not fire", func(t *testing.T) {
		body := `<?xml version="1.0" encoding="utf-8"?>` +
			`<Error><Code>PublicAccessNotPermitted</Code>` +
			`<Message>Public access is not permitted on this storage account.</Message></Error>`
		if res := runBucketModule(t, azure, 404, body); len(res.Findings) > 0 {
			t.Errorf("a PublicAccessNotPermitted body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a missing container returning ContainerNotFound does not fire", func(t *testing.T) {
		body := `<?xml version="1.0" encoding="utf-8"?>` +
			`<Error><Code>ContainerNotFound</Code><Message>The specified container does not exist.</Message></Error>`
		if res := runBucketModule(t, azure, 404, body); len(res.Findings) > 0 {
			t.Errorf("a ContainerNotFound body should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a normal html page does not fire", func(t *testing.T) {
		body := "<!DOCTYPE html><html><head><title>hi</title></head><body>hello</body></html>"
		if res := runBucketModule(t, azure, 200, body); len(res.Findings) > 0 {
			t.Errorf("a plain html page should not match, got %d findings", len(res.Findings))
		}
	})
}
