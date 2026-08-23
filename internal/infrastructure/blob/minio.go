// Package blob provides content-addressed artifact storage for the evidence vault
// a MinIO/S3 adapter for deployments and an in-memory store for dev/tests.
// Keys are the artifact's lowercase-hex SHA-256, so identical content dedups and
// the stored bytes stay verifiable against the evidence chain.
package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Config configures the MinIO/S3 blob store.
type Config struct {
	Endpoint  string // host:port (no scheme)
	AccessKey string
	SecretKey string
	Bucket    string
	UseSSL    bool
}

// ObjectMetadata is integrity metadata derived from an object. SHA256 is never
// inferred from an object key or trusted solely from object metadata.
type ObjectMetadata = ports.ObjectMetadata

// ReadOnlyMinIO exposes only restore-verification operations. It intentionally
// has no Put method so a restore caller cannot obtain write capability.
type ReadOnlyMinIO struct {
	client *minio.Client
	bucket string
}

// MinIO is an S3-compatible content-addressed BlobStore.
type MinIO struct {
	client *minio.Client
	bucket string
}

var _ ports.BlobStore = (*MinIO)(nil)
var _ ports.RestoreBlobReader = (*ReadOnlyMinIO)(nil)

// NewMinIO connects to the object store and ensures the bucket exists.
func NewMinIO(ctx context.Context, cfg Config) (*MinIO, error) {
	client, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("minio bucket check: %w", err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{}); err != nil {
			return nil, fmt.Errorf("minio make bucket: %w", err)
		}
	}
	return &MinIO{client: client, bucket: cfg.Bucket}, nil
}

// NewReadOnlyMinIO connects to an existing object store without creating or
// modifying the bucket. Its result is capability-constrained to read-only
// verification methods for future restore ports.
func NewReadOnlyMinIO(ctx context.Context, cfg Config) (*ReadOnlyMinIO, error) {
	client, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	exists, err := client.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("minio bucket check: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("minio bucket check: bucket is missing")
	}
	return &ReadOnlyMinIO{client: client, bucket: cfg.Bucket}, nil
}

func newClient(cfg Config) (*minio.Client, error) {
	if cfg.Endpoint == "" || cfg.Bucket == "" {
		return nil, fmt.Errorf("%w: blob store requires endpoint and bucket", shared.ErrValidation)
	}
	if (cfg.AccessKey == "") != (cfg.SecretKey == "") {
		return nil, fmt.Errorf("%w: blob access and secret keys must be set together", shared.ErrValidation)
	}
	creds := credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, "")
	if cfg.AccessKey == "" {
		// NewIAM follows the AWS container, web-identity, and EC2 metadata credential
		// paths, so the same runtime supports EKS IRSA and EC2 instance profiles.
		creds = credentials.NewIAM("")
	}
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  creds,
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("minio client: %w", err)
	}
	return client, nil
}

// Put stores data under the content-addressed key. Idempotent: re-putting the same
// content-addressed key is a harmless overwrite of identical bytes. (Object
// retention/immutability is a deployment-side concern.)
func (m *MinIO) Put(ctx context.Context, key string, data []byte) error {
	if _, err := m.client.PutObject(ctx, m.bucket, key, bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: "application/octet-stream"}); err != nil {
		return fmt.Errorf("put artifact: %w", err)
	}
	return nil
}

// Get returns the bytes stored under key (shared.ErrNotFound if absent).
func (m *MinIO) Get(ctx context.Context, key string) ([]byte, error) {
	return get(m.client, ctx, m.bucket, key)
}

// Stat reads and hashes the object so metadata-less legacy objects are verified
// securely. Object contents never appear in errors or logs.
func (m *ReadOnlyMinIO) Stat(ctx context.Context, key string) (ObjectMetadata, error) {
	return stat(m.client, ctx, m.bucket, key)
}

// Verify hashes object content and compares it to expected without exposing the
// object's bytes to the restore caller.
func (m *ReadOnlyMinIO) Verify(ctx context.Context, key, expected string) error {
	return verify(m.client, ctx, m.bucket, key, expected)
}

func get(client *minio.Client, ctx context.Context, bucket, key string) ([]byte, error) {
	obj, err := client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, minioGetError("get artifact", err)
	}
	defer func() { _ = obj.Close() }()
	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, minioGetError("read artifact", err)
	}
	return data, nil
}

func stat(client *minio.Client, ctx context.Context, bucket, key string) (ObjectMetadata, error) {
	obj, err := client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return ObjectMetadata{}, minioGetError("get artifact", err)
	}
	defer func() { _ = obj.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, obj); err != nil {
		return ObjectMetadata{}, minioGetError("verify artifact", err)
	}
	return ObjectMetadata{SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func verify(client *minio.Client, ctx context.Context, bucket, key, expected string) error {
	obj, err := client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return minioGetError("get artifact", err)
	}
	defer func() { _ = obj.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, obj); err != nil {
		return minioGetError("verify artifact", err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return fmt.Errorf("artifact checksum does not match expected SHA-256")
	}
	return nil
}

func minioGetError(operation string, err error) error {
	if minio.ToErrorResponse(err).Code == "NoSuchKey" {
		return shared.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}

// CheckReady verifies that the configured evidence bucket remains reachable. It performs no object
// reads or writes and is safe to call from the unauthenticated readiness endpoint.
func (m *MinIO) CheckReady(ctx context.Context) error {
	exists, err := m.client.BucketExists(ctx, m.bucket)
	if err != nil {
		return fmt.Errorf("minio bucket readiness: %w", err)
	}
	if !exists {
		return fmt.Errorf("minio bucket readiness: bucket is missing")
	}
	return nil
}
