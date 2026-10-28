package documentproviders

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The live suite runs the publication lifecycle against a real S3 implementation
// and is opt-in, like the Postgres and syslog suites. Set:
//
//	SYNAPSE_TEST_S3_ENDPOINT    host:port or URL of the S3 API, for example
//	                            127.0.0.1:9000 for the dev MinIO in
//	                            deploy/docker-compose.yml.
//	SYNAPSE_TEST_S3_ACCESS_KEY  access key ID
//	SYNAPSE_TEST_S3_SECRET_KEY  secret access key
//	SYNAPSE_TEST_S3_BUCKET      bucket to use; the suite creates it when missing,
//	                            enables versioning, and installs the reader policy
//	SYNAPSE_TEST_S3_REGION      optional, default us-east-1
//	SYNAPSE_TEST_S3_SECURE      optional, set to 1 for an https endpoint
//
// What a fake cannot prove is here: that a real implementation accepts the
// zero-length stamped shell, enforces ETag content preconditions, reports
// the policy Synapse installed, and removes every version on purge.
const (
	envS3Endpoint  = "SYNAPSE_TEST_S3_ENDPOINT"
	envS3AccessKey = "SYNAPSE_TEST_S3_ACCESS_KEY"
	envS3SecretKey = "SYNAPSE_TEST_S3_SECRET_KEY"
	envS3Bucket    = "SYNAPSE_TEST_S3_BUCKET"
	envS3Region    = "SYNAPSE_TEST_S3_REGION"
	envS3Secure    = "SYNAPSE_TEST_S3_SECURE"
)

const liveReader = "arn:aws:iam::123456789012:role/synapse-live-readers"

func liveS3Adapter(t *testing.T) (*s3Adapter, string) {
	t.Helper()
	endpoint, access, secret, bucket := os.Getenv(envS3Endpoint), os.Getenv(envS3AccessKey), os.Getenv(envS3SecretKey), os.Getenv(envS3Bucket)
	if endpoint == "" || access == "" || secret == "" || bucket == "" {
		t.Skipf("set %s, %s, %s and %s to run the live S3 suite", envS3Endpoint, envS3AccessKey, envS3SecretKey, envS3Bucket)
	}
	host := endpoint
	if strings.Contains(endpoint, "://") {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			t.Fatalf("parse %s: %v", envS3Endpoint, err)
		}
		host = parsed.Host
	}
	region := os.Getenv(envS3Region)
	if region == "" {
		region = "us-east-1"
	}
	secure := os.Getenv(envS3Secure) == "1"
	client, err := minio.New(host, &minio.Options{Creds: credentials.NewStaticV4(access, secret, ""), Secure: secure, Region: region, MaxRetries: 1})
	if err != nil {
		t.Fatalf("live client: %v", err)
	}
	prefix := "synapse-live"
	scheme := "http://"
	if secure {
		scheme = "https://"
	}
	return &s3Adapter{
		client: client, bucket: bucket, prefix: prefix, principal: liveReader,
		endpoint: scheme + host, readEndpoint: scheme + host + "/" + bucket, accessKey: access, secretKey: secret,
	}, prefix
}

func liveReaderPolicy(bucket, prefix string) string {
	return `{"Version":"2012-10-17","Statement":[{"Sid":"synapse-live-readers","Effect":"Allow","Principal":{"AWS":["` +
		liveReader + `"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::` + bucket + `/` + prefix + `/*"]}]}`
}

func liveS3Prepare(t *testing.T, adapter *s3Adapter, prefix string) {
	t.Helper()
	ctx := context.Background()
	exists, err := adapter.client.BucketExists(ctx, adapter.bucket)
	if err != nil {
		t.Fatalf("bucket exists: %v", err)
	}
	if !exists {
		if err = adapter.client.MakeBucket(ctx, adapter.bucket, minio.MakeBucketOptions{}); err != nil {
			t.Fatalf("make bucket: %v", err)
		}
	}
	if err = adapter.client.EnableVersioning(ctx, adapter.bucket); err != nil {
		t.Fatalf("enable versioning: %v", err)
	}
	if err = adapter.client.SetBucketPolicy(ctx, adapter.bucket, liveReaderPolicy(adapter.bucket, prefix)); err != nil {
		t.Fatalf("set reader policy: %v", err)
	}
}

func liveS3Clean(t *testing.T, adapter *s3Adapter, marker string) {
	t.Helper()
	ctx := context.Background()
	for item := range adapter.client.ListObjects(ctx, adapter.bucket, minio.ListObjectsOptions{Prefix: adapter.publicationPrefix(marker), Recursive: true, WithVersions: true}) {
		if item.Err != nil {
			return
		}
		_ = adapter.client.RemoveObject(ctx, adapter.bucket, item.Key, minio.RemoveObjectOptions{VersionID: item.VersionID})
	}
}

func TestS3LiveLifecycle(t *testing.T) {
	adapter, prefix := liveS3Adapter(t)
	liveS3Prepare(t, adapter, prefix)
	ctx := context.Background()
	marker := fmt.Sprintf("synapse-intent-live-%d", time.Now().UTC().Unix())
	liveS3Clean(t, adapter, marker)
	t.Cleanup(func() { liveS3Clean(t, adapter, marker) })

	if err := adapter.TestConnection(ctx); err != nil {
		t.Fatalf("connection test: %v", err)
	}
	page, err := adapter.CreateDocumentShell(ctx, adapter.bucket, marker)
	if err != nil {
		t.Fatalf("create shell: %v", err)
	}
	state, err := adapter.ReadRestrictedDocument(ctx, page.ID, adapter.bucket, liveReader)
	if err != nil {
		t.Fatalf("read neutral shell: %v", err)
	}
	if !state.Neutral {
		t.Fatalf("a fresh shell must be neutral: %+v", state)
	}
	if err = adapter.UploadDocumentAttachment(ctx, page.ID, ports.DocumentImage{Name: "chart.png", MediaType: "image/png", Data: []byte("live-image-bytes")}); err != nil {
		t.Fatalf("upload attachment: %v", err)
	}
	written, err := adapter.WriteDocumentRevision(ctx, page, "Live engagement report", `<h1>Live</h1><p>finding</p><p><image><attachment filename="chart.png"></attachment></image></p>`, marker)
	if err != nil {
		t.Fatalf("write body: %v", err)
	}
	if written.Revision == "" || written.Revision == page.Revision {
		t.Fatalf("the write must return a new opaque content revision: %+v", written)
	}
	current, err := adapter.GetDocument(ctx, page.ID)
	if err != nil {
		t.Fatalf("read document: %v", err)
	}
	if current.Title != "Live engagement report" || current.Neutral || current.Revision != written.Revision {
		t.Fatalf("stored state = %+v", current)
	}
	if _, err = adapter.WriteDocumentRevision(ctx, page, "Stale", "<p>stale</p>", marker); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("the stale revision must conflict, got %v", err)
	}

	// A real public grant must refuse the next write and report the breach.
	public := `{"Version":"2012-10-17","Statement":[{"Sid":"public","Effect":"Allow","Principal":"*","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::` + adapter.bucket + `/` + prefix + `/*"]}]}`
	if err = adapter.client.SetBucketPolicy(ctx, adapter.bucket, public); err != nil {
		t.Fatalf("set public policy: %v", err)
	}
	_, err = adapter.WriteDocumentRevision(ctx, current.RemotePage, "Public", "<p>public</p>", marker)
	var refusal *ports.DocumentProviderError
	if !errors.As(err, &refusal) || refusal.Code != "public_bucket_policy" || !refusal.RestrictionLost {
		t.Fatalf("a public bucket must report a lost restriction, got %v", err)
	}
	if err = adapter.client.SetBucketPolicy(ctx, adapter.bucket, liveReaderPolicy(adapter.bucket, prefix)); err != nil {
		t.Fatalf("restore reader policy: %v", err)
	}

	if err = adapter.PurgeDocument(ctx, page.ID, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("purge: %v", err)
	}
	remaining := 0
	for item := range adapter.client.ListObjects(ctx, adapter.bucket, minio.ListObjectsOptions{Prefix: adapter.publicationPrefix(marker), Recursive: true, WithVersions: true}) {
		if item.Err != nil {
			t.Fatalf("list after purge: %v", item.Err)
		}
		remaining++
	}
	if remaining != 0 {
		t.Fatalf("%d versions remain after the purge", remaining)
	}
}

// beforeS3PutTransport injects a real competing S3 write immediately before the
// adapter's conditional request reaches the same backend.
type beforeS3PutTransport struct {
	base   http.RoundTripper
	before func()
}

func (t beforeS3PutTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodPut && strings.HasSuffix(request.URL.Path, "/"+s3BodyName) {
		t.before()
	}
	return t.base.RoundTrip(request)
}

func TestS3LiveContentRaceAndHistory(t *testing.T) {
	adapter, prefix := liveS3Adapter(t)
	liveS3Prepare(t, adapter, prefix)
	ctx := context.Background()
	marker := fmt.Sprintf("synapse-intent-content-%d", time.Now().UTC().UnixNano())
	t.Cleanup(func() { liveS3Clean(t, adapter, marker) })
	page, err := adapter.CreateDocumentShell(ctx, adapter.bucket, marker)
	if err != nil {
		t.Fatal(err)
	}
	written, err := adapter.WriteDocumentRevision(ctx, page, "Initial", "<p>initial</p>", marker)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := adapter.WriteDocumentRevision(ctx, written, "Republished", "<p>republished</p>", marker+"-next")
	if err != nil {
		t.Fatalf("first republish: %v", err)
	}
	originalClient := adapter.client
	competingBody := s3Document(t, "Competing", "<p>competing</p>")
	var once sync.Once
	competing := beforeS3PutTransport{base: http.DefaultTransport, before: func() {
		once.Do(func() {
			_, putErr := originalClient.PutObject(ctx, adapter.bucket, adapter.key(marker, s3BodyName), bytes.NewReader(competingBody), int64(len(competingBody)), minio.PutObjectOptions{
				ContentType: "text/html; charset=utf-8", UserMetadata: map[string]string{s3MarkerMeta: marker}, DisableMultipart: true,
			})
			if putErr != nil {
				t.Fatalf("competing backend write: %v", putErr)
			}
		})
	}}
	endpoint, _ := url.Parse(adapter.endpoint)
	adapter.client, err = minio.New(endpoint.Host, &minio.Options{Creds: credentials.NewStaticV4(adapter.accessKey, adapter.secretKey, ""), Secure: endpoint.Scheme == "https", Region: func() string {
		if r := os.Getenv(envS3Region); r != "" {
			return r
		}
		return "us-east-1"
	}(), Transport: competing, MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.WriteDocumentRevision(ctx, updated, "Stale", "<p>stale</p>", marker+"-stale")
	if refusal := s3Refusal(t, err); refusal.Code != "revision_conflict" || refusal.Ambiguous {
		t.Fatalf("real backend accepted a stale If-Match: %+v", refusal)
	}
	adapter.client = originalClient
	current, err := adapter.GetDocument(ctx, marker)
	if err != nil || current.Title != "Competing" {
		t.Fatalf("concurrent backend content was overwritten: %+v, %v", current, err)
	}
	for i := 0; i < 65; i++ {
		_, err = originalClient.PutObject(ctx, adapter.bucket, adapter.key(marker, s3BodyName), bytes.NewReader(competingBody), int64(len(competingBody)), minio.PutObjectOptions{
			ContentType: "text/html; charset=utf-8", UserMetadata: map[string]string{s3MarkerMeta: marker}, DisableMultipart: true,
		})
		if err != nil {
			t.Fatalf("seed real version history: %v", err)
		}
	}
	if _, err = adapter.GetDocument(ctx, marker); err != nil {
		t.Fatalf("65 historical writes blocked current read: %v", err)
	}
	if err = adapter.PurgeDocument(ctx, marker, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("real paginated history purge: %v", err)
	}
	versions, err := adapter.allVersions(ctx, marker)
	if err != nil || len(versions) != 0 {
		t.Fatalf("history remains after purge: %d, %v", len(versions), err)
	}
}

func TestS3LiveLegalHold(t *testing.T) {
	adapter, prefix := liveS3Adapter(t)
	adapter.bucket += "-lock"
	ctx := context.Background()
	exists, err := adapter.client.BucketExists(ctx, adapter.bucket)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		if err = adapter.client.MakeBucket(ctx, adapter.bucket, minio.MakeBucketOptions{ObjectLocking: true}); err != nil {
			t.Fatal(err)
		}
	}
	liveS3Prepare(t, adapter, prefix)
	marker := fmt.Sprintf("synapse-intent-held-%d", time.Now().UTC().UnixNano())
	page, err := adapter.CreateDocumentShell(ctx, adapter.bucket, marker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = adapter.WriteDocumentRevision(ctx, page, "Held", "<p>held</p>", marker); err != nil {
		t.Fatal(err)
	}
	versions, err := adapter.allVersions(ctx, marker)
	if err != nil {
		t.Fatal(err)
	}
	body := versions[0]
	for _, version := range versions {
		if strings.HasSuffix(version.key, "/"+s3BodyName) {
			body = version
		}
	}
	setHold := func(hold minio.LegalHoldStatus) error {
		return adapter.client.PutObjectLegalHold(ctx, adapter.bucket, body.key, minio.PutObjectLegalHoldOptions{VersionID: body.versionID, Status: &hold})
	}
	t.Cleanup(func() {
		_ = setHold(minio.LegalHoldDisabled)
		liveS3Clean(t, adapter, marker)
	})
	if err = setHold(minio.LegalHoldEnabled); err != nil {
		t.Fatal(err)
	}
	err = adapter.PurgeDocument(ctx, marker, func(context.Context) error { return nil })
	if refusal := s3Refusal(t, err); refusal.Code != "object_lock_retained" {
		t.Fatalf("real legal hold was not recognized: %+v", refusal)
	}
	remaining, err := adapter.allVersions(ctx, marker)
	if err != nil || len(remaining) != len(versions) {
		t.Fatalf("held publication was partly deleted: before=%d after=%d err=%v", len(versions), len(remaining), err)
	}
	if err = setHold(minio.LegalHoldDisabled); err != nil {
		t.Fatal(err)
	}
	if err = adapter.PurgeDocument(ctx, marker, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("unheld, lock-enabled publication could not be purged: %v", err)
	}
}
