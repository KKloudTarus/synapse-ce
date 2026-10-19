package storetest

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type dispatchStore interface {
	ports.TicketStore
	ports.TicketDispatchStore
}

// Dispatch is the cross-adapter contract for the durable provider-write fence.
func Dispatch(t *testing.T, store dispatchStore, f Fixture) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	makeIntent := func(id, key string) ticketing.Intent {
		return ticketing.Intent{ID: shared.ID(id), TenantID: f.Tenant, IntegrationID: f.Integration, MappingID: "ticket-map-a", FindingID: f.Finding, EngagementID: f.Engagement, Action: ticketing.Create, RequestKey: key, PayloadDigest: strings.Repeat("a", 64), Marker: "synapse-intent-" + id, State: writeintent.Pending, Version: 1, MappingVersion: 1, ConnectionRevision: 1, CredentialRevision: 1, Snapshot: []byte(`{"fields":{"project":{"key":"SEC"},"issuetype":{"id":"Bug"}}}`), CreatedAt: now, UpdatedAt: now}
	}
	first, second := makeIntent("ticket-dispatch-one", "dispatch-one"), makeIntent("ticket-dispatch-two", "dispatch-two")
	for _, intent := range []ticketing.Intent{first, second} {
		if _, created, err := store.CreateOrGetIntent(ctx, f.Tenant, intent); err != nil || !created {
			t.Fatalf("create dispatch intent %s: created=%t err=%v", intent.ID, created, err)
		}
	}
	lease := now.Add(time.Minute)
	var wg sync.WaitGroup
	results := make(chan struct {
		i   ticketing.Intent
		ok  bool
		err error
	}, 2)
	for _, intent := range []ticketing.Intent{first, second} {
		wg.Add(1)
		go func(v ticketing.Intent) {
			defer wg.Done()
			got, ok, err := store.AcquireDispatch(ctx, f.Tenant, v.ID, 1, now, lease)
			results <- struct {
				i   ticketing.Intent
				ok  bool
				err error
			}{got, ok, err}
		}(intent)
	}
	wg.Wait()
	close(results)
	var winner ticketing.Intent
	wins := 0
	for r := range results {
		if r.err != nil {
			t.Fatalf("concurrent acquire: %v", r.err)
		}
		if r.ok {
			wins++
			winner = r.i
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent tuple claims=%d, want 1", wins)
	}
	failed, err := store.FinishDispatch(ctx, f.Tenant, winner.ID, winner.Version, ticketing.IntentTransition{Event: writeintent.Reject, ErrorCode: "provider_rejected"}, now.Add(time.Second), nil, "http_401")
	if err != nil || failed.State != writeintent.Failed {
		t.Fatalf("finish 401: %+v %v", failed, err)
	}
	other := second
	if winner.ID == second.ID {
		other = first
	}
	if _, ok, err := store.AcquireDispatch(ctx, f.Tenant, other.ID, 1, now.Add(2*time.Second), now.Add(2*time.Minute)); err != nil || ok {
		t.Fatalf("opened breaker allowed claim: ok=%t err=%v", ok, err)
	}
	audit := ports.AuditEntry{Actor: "admin", Action: "ticket.breaker.reset", Target: string(f.Integration), At: now.Add(3 * time.Second)}
	if err := store.ResetBreaker(ctx, f.Other, f.Integration, "SEC", "Bug", audit); err == nil {
		t.Fatal("cross-tenant reset accepted")
	}
	if err := store.ResetBreaker(ctx, f.Tenant, f.Integration, "SEC", "Bug", audit); err != nil {
		t.Fatalf("reset breaker: %v", err)
	}
	active, ok, err := store.AcquireDispatch(ctx, f.Tenant, other.ID, 1, now.Add(4*time.Second), now.Add(5*time.Minute))
	if err != nil || !ok {
		t.Fatalf("claim after reset: ok=%t err=%v", ok, err)
	}
	// An explicit retry cannot queue alongside another unresolved create.
	if _, err = store.RetryIntentAudited(ctx, f.Tenant, winner.ID, failed.Version, now.Add(4*time.Second), ports.AuditEntry{Actor: "admin", Action: "ticket.intent.retry_duplicate_risk", Target: winner.ID.String(), At: now.Add(4 * time.Second)}); err == nil {
		t.Fatal("retry bypassed active create fence")
	}
	if unchanged, e := store.GetIntent(ctx, f.Tenant, winner.ID); e != nil || unchanged.State != writeintent.Failed || unchanged.Version != failed.Version {
		t.Fatalf("refused retry mutated failed intent: %+v %v", unchanged, e)
	}
	fenced := makeIntent("ticket-dispatch-fenced", "dispatch-fenced")
	if _, _, err = store.CreateOrGetIntent(ctx, f.Tenant, fenced); err != nil {
		t.Fatal(err)
	}
	if _, claimed, e := store.AcquireDispatch(ctx, f.Tenant, fenced.ID, 1, now.Add(4*time.Second), now.Add(5*time.Minute)); e != nil || claimed {
		t.Fatalf("retry erased active fence: claimed=%t err=%v", claimed, e)
	}
	if err := store.ResetBreaker(ctx, f.Tenant, f.Integration, "SEC", "Bug", audit); err != nil {
		t.Fatal(err)
	}
	if _, claimed, e := store.AcquireDispatch(ctx, f.Tenant, fenced.ID, 1, now.Add(4*time.Second), now.Add(5*time.Minute)); e != nil || claimed {
		t.Fatalf("reset erased active fence: claimed=%t err=%v", claimed, e)
	}
	cooldown := now.Add(10 * time.Minute)
	if _, err = store.FinishDispatch(ctx, f.Tenant, active.ID, active.Version, ticketing.IntentTransition{Event: writeintent.Reject, ErrorCode: "provider_rejected"}, now.Add(5*time.Second), &cooldown, "http_429"); err != nil {
		t.Fatalf("finish 429: %v", err)
	}
	if err := store.ResetBreaker(ctx, f.Tenant, f.Integration, "SEC", "Bug", audit); err == nil {
		t.Fatal("reset bypassed Retry-After")
	}
	third := makeIntent("ticket-dispatch-three", "dispatch-three")
	if _, _, err = store.CreateOrGetIntent(ctx, f.Tenant, third); err != nil {
		t.Fatal(err)
	}
	if _, ok, err = store.AcquireDispatch(ctx, f.Tenant, third.ID, 1, cooldown.Add(-time.Nanosecond), cooldown.Add(time.Minute)); err != nil || ok {
		t.Fatalf("cooldown admitted early: ok=%t err=%v", ok, err)
	}
	if due, err := store.ListDueIntents(ctx, f.Tenant, cooldown.Add(-time.Nanosecond), 200); err != nil {
		t.Fatalf("list due while cooled down: %v", err)
	} else {
		for _, intent := range due {
			if intent.ID == third.ID {
				t.Fatal("rate-limited pending intent starved the due page")
			}
		}
	}
	claimed, ok, err := store.AcquireDispatch(ctx, f.Tenant, third.ID, 1, cooldown, cooldown.Add(time.Minute))
	if err != nil || !ok {
		t.Fatalf("cooldown boundary claim: ok=%t err=%v", ok, err)
	}
	fourth := makeIntent("ticket-dispatch-four", "dispatch-four")
	if _, _, err = store.CreateOrGetIntent(ctx, f.Tenant, fourth); err != nil {
		t.Fatal(err)
	}
	next, ok, err := store.AcquireDispatch(ctx, f.Tenant, fourth.ID, 1, cooldown.Add(time.Minute), cooldown.Add(2*time.Minute))
	if err != nil || !ok {
		t.Fatalf("expired lease successor: ok=%t err=%v", ok, err)
	}
	expired, err := store.GetIntent(ctx, f.Tenant, claimed.ID)
	if err != nil || expired.State != writeintent.Uncertain {
		t.Fatalf("expired intent=%+v err=%v", expired, err)
	}
	if _, _, err = store.AcquireDispatch(ctx, f.Tenant, claimed.ID, expired.Version, cooldown.Add(time.Minute), cooldown.Add(2*time.Minute)); err == nil {
		t.Fatal("uncertain intent reclaimed")
	}
	remote := ticketing.RemoteTicket{ID: "SEC-99", URL: "https://jira.example/browse/SEC-99"}
	done, err := store.FinishDispatch(ctx, f.Tenant, next.ID, next.Version, ticketing.IntentTransition{Event: writeintent.Acknowledge, Remote: &remote}, cooldown.Add(time.Minute+time.Second), nil, "")
	if err != nil || done.State != writeintent.Done {
		t.Fatalf("ack completion: %+v %v", done, err)
	}
	links, err := store.ListLinks(ctx, f.Tenant, f.Finding)
	if err != nil || len(links) == 0 {
		t.Fatalf("completion link: %+v %v", links, err)
	}
	if _, err = store.FinishDispatch(ctx, f.Tenant, next.ID, next.Version, ticketing.IntentTransition{Event: writeintent.Acknowledge, Remote: &remote}, cooldown.Add(time.Minute+2*time.Second), nil, ""); err == nil {
		t.Fatal("stale finish accepted")
	}
	if _, _, err = store.AcquireDispatch(ctx, f.Other, next.ID, done.Version, now, lease); err == nil {
		t.Fatal("cross-tenant acquire accepted")
	}
	// A malformed audit decision cannot make a failed command eligible again.
	before, err := store.GetIntent(ctx, f.Tenant, winner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.RetryIntentAudited(ctx, f.Tenant, winner.ID, before.Version, cooldown.Add(2*time.Minute), ports.AuditEntry{}); err == nil {
		t.Fatal("retry accepted missing audit evidence")
	}
	after, err := store.GetIntent(ctx, f.Tenant, winner.ID)
	if err != nil || after.State != before.State || after.Version != before.Version {
		t.Fatalf("invalid-audit retry mutated intent: before=%+v after=%+v err=%v", before, after, err)
	}
}

// StatusRefusalDoesNotGateTuple proves a bad per-ticket status command cannot
// stop unrelated work for the shared Jira destination. Creates keep their
// tuple-wide credential and mapping refusal fence; status commands have their
// own durable request-key fence instead.
func StatusRefusalDoesNotGateTuple(t *testing.T, store dispatchStore, f Fixture) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 2, 2, 10, 0, 0, 0, time.UTC)
	makeIntent := func(id string, action ticketing.Action) ticketing.Intent {
		return ticketing.Intent{ID: shared.ID(id), TenantID: f.Tenant, IntegrationID: f.Integration, MappingID: "ticket-map-a", FindingID: f.Finding, EngagementID: f.Engagement, Action: action, RequestKey: "status-refusal-" + id, PayloadDigest: strings.Repeat("b", 64), Marker: "synapse-intent-" + id, State: writeintent.Pending, Version: 1, MappingVersion: 1, ConnectionRevision: 1, CredentialRevision: 1, Snapshot: []byte(`{"fields":{"project":{"key":"SEC"},"issuetype":{"id":"Bug"}}}`), CreatedAt: now, UpdatedAt: now}
	}
	for _, refusal := range []struct {
		name   string
		action ticketing.Action
		code   string
	}{
		{name: "transition-400", action: ticketing.Transition, code: "http_400"},
		{name: "comment-404", action: ticketing.Comment, code: "http_404"},
		{name: "update-400", action: ticketing.Update, code: "http_400"},
	} {
		t.Run(refusal.name, func(t *testing.T) {
			bad := makeIntent("ticket-status-"+refusal.name, refusal.action)
			good := makeIntent("ticket-create-after-"+refusal.name, ticketing.Create)
			otherStatus := makeIntent("ticket-status-after-"+refusal.name, ticketing.Update)
			for _, intent := range []ticketing.Intent{bad, good, otherStatus} {
				if _, created, err := store.CreateOrGetIntent(ctx, f.Tenant, intent); err != nil || !created {
					t.Fatalf("create %s: created=%t err=%v", intent.ID, created, err)
				}
			}
			claimed, ok, err := store.AcquireDispatch(ctx, f.Tenant, bad.ID, bad.Version, now, now.Add(time.Minute))
			if err != nil || !ok {
				t.Fatalf("claim refused status command: ok=%t err=%v", ok, err)
			}
			failed, err := store.FinishDispatch(ctx, f.Tenant, claimed.ID, claimed.Version, ticketing.IntentTransition{Event: writeintent.Reject, ErrorCode: refusal.code}, now.Add(time.Second), nil, refusal.code)
			if err != nil || failed.State != writeintent.Failed {
				t.Fatalf("finish refused status command: %+v err=%v", failed, err)
			}
			goodClaim, ok, err := store.AcquireDispatch(ctx, f.Tenant, good.ID, good.Version, now.Add(2*time.Second), now.Add(2*time.Minute))
			if err != nil || !ok {
				t.Fatalf("status refusal blocked unrelated create: ok=%t err=%v", ok, err)
			}
			remote := ticketing.RemoteTicket{ID: "SEC-" + refusal.name, URL: "https://jira.example/browse/SEC-" + refusal.name}
			if _, err = store.FinishDispatch(ctx, f.Tenant, goodClaim.ID, goodClaim.Version, ticketing.IntentTransition{Event: writeintent.Acknowledge, Remote: &remote}, now.Add(3*time.Second), nil, ""); err != nil {
				t.Fatalf("finish unrelated create: %v", err)
			}
			otherClaim, ok, err := store.AcquireDispatch(ctx, f.Tenant, otherStatus.ID, otherStatus.Version, now.Add(4*time.Second), now.Add(5*time.Minute))
			if err != nil || !ok {
				t.Fatalf("status refusal blocked unrelated status command: ok=%t err=%v", ok, err)
			}
			if _, err = store.FinishDispatch(ctx, f.Tenant, otherClaim.ID, otherClaim.Version, ticketing.IntentTransition{Event: writeintent.Reject, ErrorCode: "invalid_action"}, now.Add(5*time.Second), nil, "invalid_action"); err != nil {
				t.Fatalf("finish unrelated status command: %v", err)
			}
		})
	}
}
