package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func TestMinIOCheckReadyUsesBucketProbe(t *testing.T) {
	headStatus := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/evidence/" {
			t.Errorf("unexpected readiness request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}

		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`))
		case http.MethodHead:
			w.WriteHeader(headStatus)
		default:
			t.Errorf("unexpected readiness request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	client, err := minio.New(strings.TrimPrefix(server.URL, "http://"), &minio.Options{
		Creds: credentials.NewStaticV4("access", "secret", ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &MinIO{client: client, bucket: "evidence"}
	if err := store.CheckReady(context.Background()); err != nil {
		t.Fatalf("reachable bucket should be ready: %v", err)
	}

	headStatus = http.StatusNotFound
	if err := store.CheckReady(context.Background()); err == nil {
		t.Fatal("missing bucket must not be ready")
	}

	server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := store.CheckReady(ctx); err == nil {
		t.Fatal("unreachable object store must not be ready")
	}
}

func TestReadOnlyMinIOStatsLegacyObjectByStreamingBytes(t *testing.T) {
	data := []byte("legacy object without checksum metadata")
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/evidence/":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`))
		case r.Method == http.MethodHead && r.URL.Path == "/evidence/":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/evidence/"+want:
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			_, _ = w.Write(data)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	store, err := NewReadOnlyMinIO(context.Background(), Config{
		Endpoint: strings.TrimPrefix(server.URL, "http://"), AccessKey: "access", SecretKey: "secret", Bucket: "evidence",
	})
	if err != nil {
		t.Fatalf("new read-only store: %v", err)
	}
	metadata, err := store.Stat(context.Background(), want)
	if err != nil {
		t.Fatalf("stat legacy object: %v", err)
	}
	if metadata.SHA256 != want {
		t.Fatalf("stat digest = %s, want %s", metadata.SHA256, want)
	}
	if err := store.Verify(context.Background(), want, want); err != nil {
		t.Fatalf("verify legacy object: %v", err)
	}
}

func TestReadOnlyMinIORejectsKeyWhoseBytesDoNotMatch(t *testing.T) {
	key := strings.Repeat("a", 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/evidence/":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`))
		case r.Method == http.MethodHead && r.URL.Path == "/evidence/":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/evidence/"+key:
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			_, _ = w.Write([]byte("corrupted object bytes"))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	store, err := NewReadOnlyMinIO(context.Background(), Config{
		Endpoint: strings.TrimPrefix(server.URL, "http://"), AccessKey: "access", SecretKey: "secret", Bucket: "evidence",
	})
	if err != nil {
		t.Fatalf("new read-only store: %v", err)
	}
	if err := store.Verify(context.Background(), key, key); err == nil {
		t.Fatal("verification must not trust the content-address key")
	}
}

func TestReadOnlyMinIODoesNotExposePut(t *testing.T) {
	var _ interface {
		Stat(context.Context, string) (ObjectMetadata, error)
		Verify(context.Context, string, string) error
	} = (*ReadOnlyMinIO)(nil)
	if _, exposesPut := any((*ReadOnlyMinIO)(nil)).(interface {
		Put(context.Context, string, []byte) error
	}); exposesPut {
		t.Fatal("read-only MinIO must not expose Put")
	}
}

func TestNewClientAcceptsInstanceProfileCredentials(t *testing.T) {
	client, err := newClient(Config{Endpoint: "s3.us-east-1.amazonaws.com", Bucket: "evidence", UseSSL: true})
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("instance-profile client is required")
	}
}

func TestNewClientRejectsPartialStaticCredentials(t *testing.T) {
	for _, cfg := range []Config{
		{Endpoint: "s3.us-east-1.amazonaws.com", Bucket: "evidence", AccessKey: "access"},
		{Endpoint: "s3.us-east-1.amazonaws.com", Bucket: "evidence", SecretKey: "secret"},
	} {
		if _, err := newClient(cfg); err == nil {
			t.Fatal("partial static credentials must fail closed")
		}
	}
}
