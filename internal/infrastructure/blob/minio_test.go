package blob

import (
	"context"
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
