package composition

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type documentPublicationTestTenants []shared.ID

func (t documentPublicationTestTenants) ListTenantIDs(context.Context) ([]shared.ID, error) {
	return t, nil
}

type documentPublicationTestTicker struct {
	seen  []shared.ID
	limit int
	err   error
}

func (t *documentPublicationTestTicker) Tick(_ context.Context, tenant shared.ID, limit int) error {
	t.seen = append(t.seen, tenant)
	t.limit = limit
	return t.err
}

func TestDocumentPublicationRunnerBoundsAndRotatesTenantWork(t *testing.T) {
	var logs bytes.Buffer
	ticker := &documentPublicationTestTicker{err: errors.New("private confluence response")}
	tenants := documentPublicationTestTenants{"", "tenant-1", "tenant-2", "tenant-3", "tenant-4", "tenant-5", "tenant-6", "tenant-7", "tenant-8", "tenant-9", "tenant-10", "tenant-11"}
	runner, err := NewDocumentPublicationRunner(ticker, tenants, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	runner.tick(context.Background())
	runner.tick(context.Background())
	if ticker.limit != 20 {
		t.Fatalf("limit = %d, want 20", ticker.limit)
	}
	if len(ticker.seen) != 18 { // the empty tenant scope is never defaulted or dispatched.
		t.Fatalf("ticks = %d, want 18 (%#v)", len(ticker.seen), ticker.seen)
	}
	if reflect.DeepEqual(ticker.seen[:10], ticker.seen[10:]) {
		t.Fatalf("tenant rounds did not rotate: %#v", ticker.seen)
	}
	if bytes.Contains(logs.Bytes(), []byte("private confluence response")) {
		t.Fatal("remote error was reflected in logs")
	}
}

func TestNewDocumentPublicationRunnerRequiresDependencies(t *testing.T) {
	log := slog.Default()
	for _, test := range []struct {
		name string
		tick DocumentPublicationTicker
		ten  documentPublicationTestTenants
		log  *slog.Logger
	}{
		{name: "ticker", ten: documentPublicationTestTenants{"tenant"}, log: log},
		{name: "log", tick: &documentPublicationTestTicker{}, ten: documentPublicationTestTenants{"tenant"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewDocumentPublicationRunner(test.tick, test.ten, test.log); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("NewDocumentPublicationRunner error = %v", err)
			}
		})
	}
}
