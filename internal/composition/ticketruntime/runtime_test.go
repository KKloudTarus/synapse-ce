package ticketruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type testTenants []shared.ID

func (t testTenants) ListTenantIDs(context.Context) ([]shared.ID, error) { return t, nil }

type testWorkflow struct {
	seen []shared.ID
	stop context.CancelFunc
	err  error
}

func (w *testWorkflow) Tick(_ context.Context, id shared.ID, limit int) (int, error) {
	if limit != 10 {
		panic("unexpected batch")
	}
	w.seen = append(w.seen, id)
	if w.stop != nil {
		w.stop()
	}
	return 0, w.err
}
func TestRunnerRotatesBoundedTenantBatchesWithoutReflectingErrors(t *testing.T) {
	var log bytes.Buffer
	work := &testWorkflow{err: errors.New("private provider diagnostic")}
	tenants := testTenants{}
	for n := range 11 {
		tenants = append(tenants, shared.ID(fmt.Sprintf("tenant-%d", n)))
	}
	r, err := New(work, tenants, slog.New(slog.NewTextHandler(&log, nil)))
	if err != nil {
		t.Fatal(err)
	}
	r.tick(context.Background())
	r.tick(context.Background())
	if len(work.seen) != 20 || work.seen[10] != tenants[10] {
		t.Fatalf("rotation %#v", work.seen)
	}
	if strings.Contains(log.String(), "private provider diagnostic") {
		t.Fatal("provider error reflected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	work.seen = nil
	work.stop = cancel
	r.tick(ctx)
	if !reflect.DeepEqual(work.seen, []shared.ID{tenants[9]}) {
		t.Fatalf("cancel ignored %#v", work.seen)
	}
}
