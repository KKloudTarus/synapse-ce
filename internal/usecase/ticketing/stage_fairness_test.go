package ticketing_test

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	usecase "github.com/KKloudTarus/synapse-ce/internal/usecase/ticketing"
)

type stageFairnessProvider struct {
	*workflowProvider
	inboundStarted chan struct{}
}

func (p *stageFairnessProvider) GetTicket(ctx context.Context, _ string) (ports.TicketObservation, error) {
	select {
	case p.inboundStarted <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ports.TicketObservation{}, ctx.Err()
}

type stageFairnessProviders struct{ provider ports.TicketProvider }

func (r stageFairnessProviders) TicketProvider(context.Context, integration.Integration) (ports.TicketProvider, error) {
	return r.provider, nil
}

func TestWorkflowTickRunsOutboundBeforeBoundedInboundRead(t *testing.T) {
	f := newWorkflowFixture(t)
	mapping := f.mapping(t, "security-1")
	first := f.submit(t, mapping, "inbound-target")
	if completed, err := f.workflow.Tick(context.Background(), "tenant-a", 10); err != nil || completed != 1 {
		t.Fatalf("complete initial intent: completed=%d err=%v", completed, err)
	}
	storedFirst, err := f.store.GetIntent(context.Background(), "tenant-a", first.ID)
	if err != nil || storedFirst.State != writeintent.Done {
		t.Fatalf("initial intent state=%s err=%v", storedFirst.State, err)
	}

	f.provider.mu.Lock()
	f.provider.created = domain.RemoteTicket{ID: "SEC-2", URL: "https://tenant.atlassian.net/browse/SEC-2"}
	f.provider.mu.Unlock()
	second := f.submit(t, mapping, "healthy-outbound")
	blocked := &stageFairnessProvider{workflowProvider: f.provider, inboundStarted: make(chan struct{}, 1)}
	workflow, err := usecase.NewWorkflow(f.store, f.integrations, stageFairnessProviders{provider: blocked}, f.findings, f.engagements, f.policy, f.audit, &ticketIDs{}, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	workflow.SetPublicBaseURL("https://console.example")

	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	completed, err := workflow.Tick(ctx, shared.ID("tenant-a"), 10)
	if err != nil || completed != 1 {
		t.Fatalf("healthy outbound was starved: completed=%d err=%v", completed, err)
	}
	select {
	case <-blocked.inboundStarted:
	default:
		t.Fatal("expected the bounded inbound stage to run")
	}
	storedSecond, err := f.store.GetIntent(context.Background(), "tenant-a", second.ID)
	if err != nil || storedSecond.State != writeintent.Done || storedSecond.RemoteID != "SEC-2" {
		t.Fatalf("healthy outbound state=%+v err=%v", storedSecond, err)
	}
}
