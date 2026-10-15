// Package storetest holds the shared memory/PostgreSQL ticketing conformance contract.
package storetest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Fixture struct {
	Tenant, Other, Integration, Project, Engagement, Finding shared.ID
}

// Run exercises identical tenant isolation, copy safety, idempotency and CAS in both adapters.
// PostgreSQL callers must first seed matching integration/engagement/finding fixtures.
func Run(t *testing.T, store ports.TicketStore, f Fixture) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mapping := ticketing.Mapping{ID: "ticket-map-a", TenantID: f.Tenant, IntegrationID: f.Integration,
		Scope: ticketing.Engagement, ScopeID: f.Engagement, ProjectKey: "SEC", IssueType: "Bug",
		SecurityLevel: "restricted", Labels: []string{"synapse"}, PriorityMap: map[string]string{"high": "Highest"},
		Version: 1, CreatedAt: now, UpdatedAt: now}
	for _, value := range []string{"label\x00", "label\xff"} {
		invalid := mapping.Clone()
		invalid.Labels = []string{value}
		if err := store.CreateMapping(ctx, f.Tenant, invalid); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("non-persistable mapping label accepted: %v", err)
		}
		invalid = mapping.Clone()
		invalid.PriorityMap = map[string]string{value: "High"}
		if err := store.CreateMapping(ctx, f.Tenant, invalid); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("non-persistable mapping priority accepted: %v", err)
		}
	}
	if err := store.CreateMapping(ctx, f.Tenant, mapping); err != nil {
		t.Fatalf("create mapping: %v", err)
	}
	if err := store.CreateMapping(ctx, f.Tenant, mapping); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate mapping: %v", err)
	}
	saved, err := store.GetMapping(ctx, f.Tenant, mapping.ID)
	if err != nil || saved.ProjectKey != "SEC" {
		t.Fatalf("mapping: %+v, %v", saved, err)
	}
	saved.Labels[0] = "mutated"
	saved.PriorityMap["high"] = "mutated"
	saved, err = store.GetMapping(ctx, f.Tenant, mapping.ID)
	if err != nil || saved.Labels[0] != "synapse" || saved.PriorityMap["high"] != "Highest" {
		t.Fatalf("mapping clone isolation: %+v, %v", saved, err)
	}
	if scoped, e := store.ListScopedMappings(ctx, f.Tenant, ticketing.Engagement, f.Engagement, 1); e != nil || len(scoped) != 1 || scoped[0].ID != mapping.ID {
		t.Fatalf("scoped mappings=%+v err=%v", scoped, e)
	}
	if scoped, e := store.ListFindingMappings(ctx, f.Tenant, f.Engagement, 1); e != nil || len(scoped) != 1 || scoped[0].ID != mapping.ID {
		t.Fatalf("finding mappings=%+v err=%v", scoped, e)
	}
	if _, err = store.GetMapping(ctx, f.Other, mapping.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant mapping lookup: %v", err)
	}

	link := ticketing.Link{ID: "ticket-link-a", TenantID: f.Tenant, EngagementID: f.Engagement,
		FindingID: f.Finding, ExternalURL: "https://jira.example/browse/SEC-12", CreatedAt: now}
	got, created, err := store.CreateLink(ctx, f.Tenant, link)
	if err != nil || !created || got.ID != link.ID {
		t.Fatalf("create manual link: %+v %t %v", got, created, err)
	}
	if loaded, e := store.GetLink(ctx, f.Tenant, link.ID); e != nil || loaded.ID != link.ID {
		t.Fatalf("get link: %+v %v", loaded, e)
	}
	repeated := link
	repeated.ID = "ticket-link-replay"
	got, created, err = store.CreateLink(ctx, f.Tenant, repeated)
	if err != nil || created || got.ID != link.ID {
		t.Fatalf("link replay: %+v %t %v", got, created, err)
	}
	repeated.IntegrationID = f.Integration
	repeated.ExternalID = "SEC-12"
	if _, _, err = store.CreateLink(ctx, f.Tenant, repeated); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("link identity mismatch: %v", err)
	}
	missingFindingLink := link
	missingFindingLink.ID = "ticket-link-missing-finding"
	missingFindingLink.FindingID = "ticket-finding-missing"
	missingFindingLink.ExternalURL = "https://jira.example/browse/MISSING"
	if _, _, err = store.CreateLink(ctx, f.Tenant, missingFindingLink); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("link accepted missing finding: %v", err)
	}
	wrongEngagementLink := link
	wrongEngagementLink.ID = "ticket-link-wrong-engagement"
	wrongEngagementLink.EngagementID = "ticket-engagement-wrong"
	wrongEngagementLink.ExternalURL = "https://jira.example/browse/WRONG-ENGAGEMENT"
	if _, _, err = store.CreateLink(ctx, f.Tenant, wrongEngagementLink); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("link accepted finding for another engagement: %v", err)
	}
	links, err := store.ListLinks(ctx, f.Other, f.Finding)
	if err != nil || links == nil || len(links) != 0 {
		t.Fatalf("cross-tenant links: %+v %v", links, err)
	}
	if err = store.DeleteLink(ctx, f.Other, link.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}

	intent := ticketing.Intent{ID: "ticket-intent-a", TenantID: f.Tenant,
		IntegrationID: f.Integration, MappingID: mapping.ID, EngagementID: f.Engagement, FindingID: f.Finding,
		Action: ticketing.Create, RequestKey: "submit-once", PayloadDigest: strings.Repeat("a", 64),
		Marker: "synapse-intent-ticket-intent-a", State: writeintent.Pending, Version: 1,
		CreatedAt: now, UpdatedAt: now}
	gotIntent, created, err := store.CreateOrGetIntent(ctx, f.Tenant, intent)
	if err != nil || !created || gotIntent.ID != intent.ID {
		t.Fatalf("create intent: %+v %t %v", gotIntent, created, err)
	}
	replay := intent
	replay.ID = "ticket-new-id"
	replay.Marker = "synapse-intent-ticket-new-id"
	gotIntent, created, err = store.CreateOrGetIntent(ctx, f.Tenant, replay)
	if err != nil || created || gotIntent.ID != intent.ID {
		t.Fatalf("intent replay: %+v %t %v", gotIntent, created, err)
	}
	replay.PayloadDigest = strings.Repeat("b", 64)
	if _, _, err = store.CreateOrGetIntent(ctx, f.Tenant, replay); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("mismatched request payload should conflict: %v", err)
	}
	if _, err = store.GetIntent(ctx, f.Other, intent.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant intent lookup: %v", err)
	}

	started := now.Add(time.Second)
	expires := started.Add(time.Minute)
	active, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 1, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &expires}, started)
	if err != nil || active.State != writeintent.InFlight || active.Attempts != 1 || active.Version != 2 {
		t.Fatalf("claim: %+v %v", active, err)
	}
	if _, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 2, ticketing.IntentTransition{Event: writeintent.Acknowledge}, started.Add(500*time.Millisecond)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("accepted completion without remote ticket: %v", err)
	}
	if unchanged, getErr := store.GetIntent(ctx, f.Tenant, intent.ID); getErr != nil || unchanged.Version != 2 || unchanged.State != writeintent.InFlight {
		t.Fatalf("invalid completion changed intent: %+v %v", unchanged, getErr)
	}
	if _, err := store.TransitionIntent(ctx, f.Other, intent.ID, 2, ticketing.IntentTransition{Event: writeintent.Acknowledge, Remote: &ticketing.RemoteTicket{ID: "SEC-12", URL: link.ExternalURL}}, started); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant transition: %v", err)
	}
	*active.LeaseUntil = started
	snapshot, err := store.GetIntent(ctx, f.Tenant, intent.ID)
	if err != nil || snapshot.LeaseUntil == nil || !snapshot.LeaseUntil.Equal(expires) {
		t.Fatalf("intent clone isolation: %+v %v", snapshot, err)
	}
	if _, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 2, ticketing.IntentTransition{Event: writeintent.Acknowledge, Remote: &ticketing.RemoteTicket{ID: "SEC-12", URL: link.ExternalURL}}, now); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nonmonotonic transition: %v", err)
	}
	if _, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 1, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &expires}, started); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale CAS: %v", err)
	}
	if _, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 2, ticketing.IntentTransition{Event: writeintent.LeaseExpired}, started.Add(time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("premature lease expiry: %v", err)
	}
	uncertain, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 2, ticketing.IntentTransition{Event: writeintent.LeaseExpired}, expires)
	if err != nil || uncertain.State != writeintent.Uncertain || uncertain.LeaseUntil != nil {
		t.Fatalf("expired lease must become uncertain: %+v %v", uncertain, err)
	}
	if _, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 3, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &expires}, expires.Add(time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("blind POST retry accepted: %v", err)
	}
	pending, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 3, ticketing.IntentTransition{Event: writeintent.ReconcileAbsent}, expires.Add(time.Second))
	if err != nil || pending.State != writeintent.Pending {
		t.Fatalf("reconcile absent: %+v %v", pending, err)
	}
	if _, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 4, ticketing.IntentTransition{Event: writeintent.Claim}, expires.Add(2*time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("claim without lease: %v", err)
	}
	expires2 := expires.Add(2 * time.Minute)
	active, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 4, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &expires2}, expires.Add(2*time.Second))
	if err != nil || active.Attempts != 2 {
		t.Fatalf("reconciled retry: %+v %v", active, err)
	}
	done, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 5, ticketing.IntentTransition{Event: writeintent.Acknowledge, Remote: &ticketing.RemoteTicket{ID: "SEC-12", URL: link.ExternalURL}}, expires.Add(3*time.Second))
	if err != nil || done.State != writeintent.Done {
		t.Fatalf("acknowledge: %+v %v", done, err)
	}
	links, err = store.ListLinks(ctx, f.Tenant, f.Finding)
	if err != nil || len(links) != 1 || links[0].ID != link.ID || links[0].IntegrationID != f.Integration || links[0].ExternalID != "SEC-12" || !links[0].CreatedAt.Equal(link.CreatedAt) {
		t.Fatalf("completion did not atomically promote manual link: %+v %v", links, err)
	}
	if _, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 6, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &expires2}, expires.Add(4*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("terminal command was retried: %v", err)
	}

	// A provider-returned marker search is the only path out of uncertain.
	intent.ID = "ticket-intent-b"
	intent.Marker = "synapse-intent-" + intent.ID.String()
	intent.RequestKey = "another-request"
	_, created, err = store.CreateOrGetIntent(ctx, f.Tenant, intent)
	if err != nil || !created {
		t.Fatalf("create second intent: %v", err)
	}
	active, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 1, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &expires}, started)
	if err != nil {
		t.Fatalf("claim second: %v", err)
	}
	uncertain, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 2, ticketing.IntentTransition{Event: writeintent.Ambiguous}, started.Add(time.Second))
	if err != nil || uncertain.State != writeintent.Uncertain {
		t.Fatalf("mark ambiguous: %+v %v", uncertain, err)
	}
	multiple, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 3, ticketing.IntentTransition{Event: writeintent.ReconcileMultiple}, started.Add(2*time.Second))
	if err != nil || multiple.State != writeintent.Uncertain || multiple.ErrorCode != "multiple_matches" || multiple.Version != 4 {
		t.Fatalf("multiple reconciliation: %+v %v", multiple, err)
	}
	if _, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 4, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &expires}, started.Add(3*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("multiple matches allowed a blind retry: %v", err)
	}
	done, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 4, ticketing.IntentTransition{Event: writeintent.ReconcileFound, Remote: &ticketing.RemoteTicket{ID: "SEC-12", URL: link.ExternalURL}}, started.Add(3*time.Second))
	if err != nil || done.State != writeintent.Done {
		t.Fatalf("reconcile found: %+v %v", done, err)
	}
	links, err = store.ListLinks(ctx, f.Tenant, f.Finding)
	if err != nil || len(links) != 1 || links[0].ID != link.ID {
		t.Fatalf("reconciliation duplicated completion link: %+v %v", links, err)
	}
	if err = store.DeleteLink(ctx, f.Tenant, link.ID); err != nil {
		t.Fatalf("delete link: %v", err)
	}
	if remaining, listErr := store.ListLinks(ctx, f.Tenant, f.Finding); listErr != nil || remaining == nil || len(remaining) != 0 {
		t.Fatalf("deleted links: %+v %v", remaining, listErr)
	}

	rejected := ticketing.Intent{ID: "ticket-intent-rejected", TenantID: f.Tenant, IntegrationID: f.Integration,
		MappingID: mapping.ID, FindingID: f.Finding, EngagementID: f.Engagement, Action: ticketing.Create,
		RequestKey: "provider-rejected", PayloadDigest: strings.Repeat("c", 64), Marker: "synapse-intent-ticket-intent-rejected",
		State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	if _, _, err = store.CreateOrGetIntent(ctx, f.Tenant, rejected); err != nil {
		t.Fatalf("create rejected intent: %v", err)
	}
	active, err = store.TransitionIntent(ctx, f.Tenant, rejected.ID, 1, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &expires}, started)
	if err != nil {
		t.Fatalf("claim rejected intent: %v", err)
	}
	if _, err = store.TransitionIntent(ctx, f.Tenant, rejected.ID, active.Version, ticketing.IntentTransition{Event: writeintent.Reject}, started.Add(time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("accepted rejection without stable error code: %v", err)
	}
	failed, err := store.TransitionIntent(ctx, f.Tenant, rejected.ID, active.Version, ticketing.IntentTransition{Event: writeintent.Reject, ErrorCode: "provider_rejected"}, started.Add(time.Second))
	if err != nil || failed.State != writeintent.Failed || failed.ErrorCode != "provider_rejected" {
		t.Fatalf("rejection classification: %+v %v", failed, err)
	}
	if _, err = store.TransitionIntent(ctx, f.Tenant, rejected.ID, failed.Version, ticketing.IntentTransition{Event: writeintent.RetryFailed, ErrorCode: "provider_rejected"}, started.Add(2*time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("accepted retry failure classification: %v", err)
	}
	pending, err = store.TransitionIntent(ctx, f.Tenant, rejected.ID, failed.Version, ticketing.IntentTransition{Event: writeintent.RetryFailed}, started.Add(2*time.Second))
	if err != nil || pending.State != writeintent.Pending || pending.ErrorCode != "" {
		t.Fatalf("retry failed did not clear classification: %+v %v", pending, err)
	}
}

// ConcurrentReplay proves an idempotency key can be won by just one caller, even
// when many requests generate different IDs before attempting to persist.
func ConcurrentReplay(t *testing.T, store ports.TicketStore, f Fixture) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m, err := store.GetMapping(ctx, f.Tenant, "ticket-map-a")
	if err != nil {
		t.Fatalf("load conformance mapping: %v", err)
	}
	const workers = 12
	type reply struct {
		id      shared.ID
		created bool
		err     error
	}
	result := make(chan reply, workers)
	var wg sync.WaitGroup
	for n := 0; n < workers; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := shared.ID("ticket-race-" + string(rune('a'+n)))
			intent := ticketing.Intent{ID: id, TenantID: f.Tenant, IntegrationID: f.Integration,
				MappingID: m.ID, FindingID: f.Finding, EngagementID: f.Engagement, Action: ticketing.Create,
				RequestKey: "race-request", PayloadDigest: strings.Repeat("f", 64),
				Marker: "synapse-intent-" + id.String(), State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
			item, created, err := store.CreateOrGetIntent(ctx, f.Tenant, intent)
			result <- reply{id: item.ID, created: created, err: err}
		}(n)
	}
	wg.Wait()
	close(result)
	count := 0
	var winner shared.ID
	for r := range result {
		if r.err != nil {
			t.Fatalf("parallel retry: %v", r.err)
		}
		if r.created {
			count++
		}
		if winner.IsZero() {
			winner = r.id
		} else if winner != r.id {
			t.Fatalf("duplicate durable intents: %s != %s", winner, r.id)
		}
	}
	if count != 1 {
		t.Fatalf("created %d intents, expected 1", count)
	}
}

// ConcurrentClaim proves a single version can be claimed by only one worker.
func ConcurrentClaim(t *testing.T, store ports.TicketStore, f Fixture) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	intent := ticketing.Intent{ID: "ticket-claim", TenantID: f.Tenant, IntegrationID: f.Integration,
		MappingID: "ticket-map-a", EngagementID: f.Engagement, FindingID: f.Finding, Action: ticketing.Create,
		RequestKey: "claim-race", PayloadDigest: strings.Repeat("a", 64), Marker: "synapse-intent-ticket-claim",
		State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
	if _, _, err := store.CreateOrGetIntent(ctx, f.Tenant, intent); err != nil {
		t.Fatal(err)
	}
	const workers = 12
	results := make(chan error, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			<-start
			lease := now.Add(time.Minute)
			_, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 1, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now)
			results <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("claim race: %v", err)
		}
	}
	got, err := store.GetIntent(ctx, f.Tenant, intent.ID)
	if err != nil || winners != 1 || got.Attempts != 1 || got.Version != 2 || got.State != writeintent.InFlight {
		t.Fatalf("claim race winners=%d intent=%+v error=%v", winners, got, err)
	}
}

// ConcurrentCompletionConflict proves that a provider-link identity conflict leaves
// the losing intent uncertain: the intent transition and its completion link form one
// atomic unit in both adapters.
func ConcurrentCompletionConflict(t *testing.T, store ports.TicketStore, f Fixture) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lease := now.Add(time.Minute)
	for _, id := range []shared.ID{"ticket-completion-a", "ticket-completion-b"} {
		intent := ticketing.Intent{ID: id, TenantID: f.Tenant, IntegrationID: f.Integration,
			MappingID: "ticket-map-a", FindingID: f.Finding, EngagementID: f.Engagement, Action: ticketing.Create,
			RequestKey: "completion-" + id.String(), PayloadDigest: strings.Repeat("d", 63) + id.String()[len(id)-1:],
			Marker: "synapse-intent-" + id.String(), State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
		if _, _, err := store.CreateOrGetIntent(ctx, f.Tenant, intent); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
		if _, err := store.TransitionIntent(ctx, f.Tenant, id, 1, ticketing.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now.Add(time.Second)); err != nil {
			t.Fatalf("claim %s: %v", id, err)
		}
		if _, err := store.TransitionIntent(ctx, f.Tenant, id, 2, ticketing.IntentTransition{Event: writeintent.Ambiguous}, now.Add(2*time.Second)); err != nil {
			t.Fatalf("mark %s uncertain: %v", id, err)
		}
	}

	results := make(chan error, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, id := range []shared.ID{"ticket-completion-a", "ticket-completion-b"} {
		wg.Add(1)
		go func(id shared.ID) {
			defer wg.Done()
			<-start
			_, err := store.TransitionIntent(ctx, f.Tenant, id, 3, ticketing.IntentTransition{
				Event:  writeintent.ReconcileFound,
				Remote: &ticketing.RemoteTicket{ID: "remote-" + id.String(), URL: "https://jira.example/browse/CONFLICT"},
			}, now.Add(3*time.Second))
			results <- err
		}(id)
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("conflicting completion: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("conflicting completions had %d winners", winners)
	}
	links, err := store.ListLinks(ctx, f.Tenant, f.Finding)
	if err != nil || len(links) != 1 || links[0].ExternalURL != "https://jira.example/browse/CONFLICT" {
		t.Fatalf("conflicting completion links: %+v %v", links, err)
	}
	done, uncertain := 0, 0
	for _, id := range []shared.ID{"ticket-completion-a", "ticket-completion-b"} {
		intent, getErr := store.GetIntent(ctx, f.Tenant, id)
		if getErr != nil {
			t.Fatal(getErr)
		}
		switch intent.State {
		case writeintent.Done:
			done++
		case writeintent.Uncertain:
			if intent.Version != 3 {
				t.Fatalf("conflicted intent was partially updated: %+v", intent)
			}
			uncertain++
		default:
			t.Fatalf("unexpected completion state: %+v", intent)
		}
	}
	if done != 1 || uncertain != 1 {
		t.Fatalf("completion states done=%d uncertain=%d", done, uncertain)
	}
}

// CanceledContext ensures no adapter performs work after cancellation.
func CanceledContext(t *testing.T, store ports.TicketStore, f Fixture) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mapping, err := store.GetMapping(context.Background(), f.Tenant, "ticket-map-a")
	if err != nil {
		t.Fatal(err)
	}
	link := ticketing.Link{ID: "ticket-canceled-link", TenantID: f.Tenant, FindingID: f.Finding,
		EngagementID: f.Engagement, ExternalURL: "https://jira.example/browse/CANCEL", CreatedAt: mapping.CreatedAt}
	intent := ticketing.Intent{ID: "ticket-canceled-intent", TenantID: f.Tenant, IntegrationID: f.Integration,
		MappingID: mapping.ID, EngagementID: f.Engagement, FindingID: f.Finding, Action: ticketing.Create,
		RequestKey: "canceled", PayloadDigest: strings.Repeat("a", 64), Marker: "synapse-intent-ticket-canceled-intent",
		State: writeintent.Pending, Version: 1, CreatedAt: mapping.CreatedAt, UpdatedAt: mapping.CreatedAt}
	checks := []struct {
		name string
		run  func() error
	}{
		{"create mapping", func() error { return store.CreateMapping(ctx, f.Tenant, mapping) }},
		{"get mapping", func() error { _, err := store.GetMapping(ctx, f.Tenant, mapping.ID); return err }},
		{"create link", func() error { _, _, err := store.CreateLink(ctx, f.Tenant, link); return err }},
		{"list links", func() error { _, err := store.ListLinks(ctx, f.Tenant, f.Finding); return err }},
		{"delete link", func() error { return store.DeleteLink(ctx, f.Tenant, link.ID) }},
		{"create intent", func() error { _, _, err := store.CreateOrGetIntent(ctx, f.Tenant, intent); return err }},
		{"get intent", func() error { _, err := store.GetIntent(ctx, f.Tenant, intent.ID); return err }},
		{"transition intent", func() error {
			_, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 1, ticketing.IntentTransition{Event: writeintent.Acknowledge}, mapping.CreatedAt)
			return err
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled operation returned %v", err)
			}
		})
	}
}
