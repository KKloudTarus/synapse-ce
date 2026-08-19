// Package blob provides content-addressed artifact storage for the evidence vault
// a MinIO/S3 adapter for deployments and an in-memory store for dev/tests.
// Keys are the artifact's lowercase-hex SHA-256, so identical content dedups and
// the stored bytes stay verifiable against the evidence chain.
package blob

import (
	"bytes"
	"context"
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

// MinIO is an S3-compatible content-addressed BlobStore.
type MinIO struct {
	client *minio.Client
	bucket string
}

var _ ports.BlobStore = (*MinIO)(nil)

// NewMinIO connects to the object store and ensures the bucket exists.
func NewMinIO(ctx context.Context, cfg Config) (*MinIO, error) {
	if cfg.Endpoint == "" || cfg.Bucket == "" {
		return nil, fmt.Errorf("%w: blob store requires endpoint and bucket", shared.ErrValidation)
	}
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("minio client: %w", err)
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
	obj, err := m.client.GetObject(ctx, m.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("get artifact: %w", err)
	}
	defer func() { _ = obj.Close() }()
	data, err := io.ReadAll(obj)
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	return data, nil
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
