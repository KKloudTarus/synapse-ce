// Package docpublishconformance runs one behavioural contract against every adapter of
// ports.DocumentStore, so the in-memory twin cannot drift from PostgreSQL unnoticed
// (EPIC #1327 D01). It is test-only support code.
package docpublishconformance

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Fixture names rows the caller seeded. Engagement and Project belong to Tenant; the Other*
// rows belong to Other. Integration belongs to Tenant.
type Fixture struct {
	Tenant, Other, Integration    shared.ID
	Engagement, Project           shared.ID
	OtherEngagement, OtherProject shared.ID
}

var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func hash(c string) string { return strings.Repeat(c, 64) }

func (f Fixture) engagementTarget(container string) docpublish.Target {
	return docpublish.Target{IntegrationID: f.Integration, SourceKind: docpublish.EngagementReport,
		SourceRef: "engagement-report", Scope: docpublish.Engagement, ScopeID: f.Engagement, Container: container}
}

func (f Fixture) projectTarget(container string) docpublish.Target {
	return docpublish.Target{IntegrationID: f.Integration, SourceKind: docpublish.AssessmentClosureReport,
		SourceRef: "cycle-1/manifest-1/v2", Scope: docpublish.Project, ScopeID: f.Project, Container: container}
}

func (f Fixture) intent(id shared.ID, target docpublish.Target, key, content string) docpublish.Intent {
	return docpublish.Intent{ID: id, TenantID: f.Tenant, Target: target, Action: docpublish.Create,
		RequestKey: key, PayloadDigest: hash("a"), ContentHash: hash(content), Marker: docpublish.MarkerFor(id),
		State: writeintent.Pending, Version: 1, CreatedAt: epoch, UpdatedAt: epoch}
}

func (f Fixture) update(id shared.ID, link docpublish.Link, key, content string) docpublish.Intent {
	i := f.intent(id, link.Target, key, content)
	i.Action = docpublish.Update
	i.LinkID = link.ID
	return i
}

func remote(id string, version int) *docpublish.RemotePage {
	return &docpublish.RemotePage{ID: id, Version: version, URL: "https://wiki.example/spaces/SEC/pages/" + id}
}

// at returns an instant n seconds after the epoch; every transition in a test moves forward.
func at(n int) time.Time { return epoch.Add(time.Duration(n) * time.Second) }

type h struct {
	t     *testing.T
	store ports.DocumentStore
	f     Fixture
}

func (x h) open(i docpublish.Intent) docpublish.Intent {
	x.t.Helper()
	got, created, err := x.store.CreateOrGetIntent(context.Background(), x.f.Tenant, i)
	if err != nil || !created || got.ID != i.ID {
		x.t.Fatalf("open intent %s: %+v created=%t err=%v", i.ID, got, created, err)
	}
	return got
}

func (x h) move(i docpublish.Intent, change docpublish.IntentTransition, when time.Time) (docpublish.Intent, error) {
	x.t.Helper()
	return x.store.TransitionIntent(context.Background(), x.f.Tenant, i.ID, i.Version, change, when)
}

func (x h) mustMove(i docpublish.Intent, change docpublish.IntentTransition, when time.Time) docpublish.Intent {
	x.t.Helper()
	got, err := x.move(i, change, when)
	if err != nil {
		x.t.Fatalf("%s on %s: %v", change.Event, i.ID, err)
	}
	return got
}

// claim leaves the intent in flight with a lease that outlives the whole test timeline.
func (x h) claim(i docpublish.Intent, n int) docpublish.Intent {
	x.t.Helper()
	lease := at(n).Add(24 * time.Hour)
	return x.mustMove(i, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, at(n))
}

func (x h) publish(i docpublish.Intent, page *docpublish.RemotePage, n int) docpublish.Intent {
	x.t.Helper()
	i = x.claim(i, n)
	return x.mustMove(i, docpublish.IntentTransition{Event: writeintent.Acknowledge, Remote: page}, at(n+1))
}

func (x h) link(target docpublish.Target) docpublish.Link {
	x.t.Helper()
	l, err := x.store.FindLink(context.Background(), x.f.Tenant, target)
	if err != nil {
		x.t.Fatalf("find link %+v: %v", target, err)
	}
	return l
}

// sameLink compares links field by field; time.Time values from different adapters can be
// equal instants with different locations, which == would report as different.
func sameLink(a, b docpublish.Link) bool {
	return a.ID == b.ID && a.TenantID == b.TenantID && a.Target == b.Target &&
		a.RemotePageID == b.RemotePageID && a.RemoteVersion == b.RemoteVersion && a.RemoteURL == b.RemoteURL &&
		a.ContentHash == b.ContentHash && a.Revision == b.Revision &&
		a.CreatedAt.Equal(b.CreatedAt) && a.UpdatedAt.Equal(b.UpdatedAt)
}

func is(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: got %v, want %v", what, err, want)
	}
}

// Run exercises tenant isolation, scope integrity, idempotency, the lifecycle and the
// atomic link write that completes an intent.
func Run(t *testing.T, store ports.DocumentStore, f Fixture) {
	t.Helper()
	ctx := context.Background()
	x := h{t: t, store: store, f: f}
	target := f.engagementTarget("SEC")

	t.Run("a command that cannot be stored is refused", func(t *testing.T) {
		invalid := f.intent("doc-invalid", target, "k-invalid", "b")
		invalid.ContentHash = "nope"
		_, _, err := store.CreateOrGetIntent(ctx, f.Tenant, invalid)
		is(t, "invalid intent", err, shared.ErrValidation)

		valid := f.intent("doc-wrong-tenant", target, "k-tenant", "b")
		_, _, err = store.CreateOrGetIntent(ctx, f.Other, valid)
		is(t, "intent for another tenant", err, shared.ErrValidation)

		started := f.intent("doc-started", target, "k-started", "b")
		started.Version = 2
		_, _, err = store.CreateOrGetIntent(ctx, f.Tenant, started)
		is(t, "intent that is not new", err, shared.ErrValidation)
	})

	t.Run("the scope parent must exist in the tenant", func(t *testing.T) {
		missing := target
		missing.ScopeID = "doc-engagement-missing"
		_, _, err := store.CreateOrGetIntent(ctx, f.Tenant, f.intent("doc-missing-scope", missing, "k-missing", "b"))
		is(t, "missing engagement", err, shared.ErrNotFound)

		foreign := target
		foreign.ScopeID = f.OtherEngagement
		_, _, err = store.CreateOrGetIntent(ctx, f.Tenant, f.intent("doc-foreign-engagement", foreign, "k-foreign", "b"))
		is(t, "another tenant's engagement", err, shared.ErrNotFound)

		foreignProject := f.projectTarget("SEC")
		foreignProject.ScopeID = f.OtherProject
		_, _, err = store.CreateOrGetIntent(ctx, f.Tenant, f.intent("doc-foreign-project", foreignProject, "k-foreign-p", "b"))
		is(t, "another tenant's project", err, shared.ErrNotFound)
	})

	first := f.intent("doc-intent-a", target, "publish-once", "b")
	t.Run("a replayed request key returns the original command", func(t *testing.T) {
		x.open(first)
		replay := first
		replay.ID = "doc-intent-replay"
		replay.Marker = docpublish.MarkerFor(replay.ID)
		got, created, err := store.CreateOrGetIntent(ctx, f.Tenant, replay)
		if err != nil || created || got.ID != first.ID {
			t.Fatalf("replay: %+v created=%t err=%v", got, created, err)
		}
		for name, mutate := range map[string]func(*docpublish.Intent){
			"payload digest": func(i *docpublish.Intent) { i.PayloadDigest = hash("c") },
			"content hash":   func(i *docpublish.Intent) { i.ContentHash = hash("c") },
			"container":      func(i *docpublish.Intent) { i.Container = "OPS" },
		} {
			changed := replay
			mutate(&changed)
			_, _, err = store.CreateOrGetIntent(ctx, f.Tenant, changed)
			is(t, "replay with a different "+name, err, shared.ErrConflict)
		}
		clash := f.intent(first.ID, target, "another-key", "b")
		_, _, err = store.CreateOrGetIntent(ctx, f.Tenant, clash)
		is(t, "reused intent ID", err, shared.ErrConflict)
	})

	t.Run("intents and links are tenant scoped", func(t *testing.T) {
		_, err := store.GetIntent(ctx, f.Other, first.ID)
		is(t, "cross-tenant intent", err, shared.ErrNotFound)
		_, err = store.GetLink(ctx, f.Tenant, "doc-no-such-link")
		is(t, "missing link", err, shared.ErrNotFound)
		_, err = store.FindLink(ctx, f.Tenant, target)
		is(t, "no link before completion", err, shared.ErrNotFound)
		links, err := store.ListLinks(ctx, f.Tenant, docpublish.Engagement, f.Engagement, 10)
		if err != nil || links == nil || len(links) != 0 {
			t.Fatalf("links before completion: %+v %v", links, err)
		}
	})

	t.Run("an update needs the link it writes to", func(t *testing.T) {
		orphan := f.update("doc-orphan", docpublish.Link{ID: "doc-link-missing", Target: target}, "k-orphan", "c")
		_, _, err := store.CreateOrGetIntent(ctx, f.Tenant, orphan)
		is(t, "update without a link", err, shared.ErrNotFound)
	})

	var created docpublish.Link
	t.Run("a completed create writes the link in the same unit", func(t *testing.T) {
		claimed := x.claim(first, 1)
		_, err := x.move(claimed, docpublish.IntentTransition{Event: writeintent.Acknowledge}, at(2))
		is(t, "completion without a page", err, shared.ErrValidation)
		unchanged, err := store.GetIntent(ctx, f.Tenant, first.ID)
		if err != nil || unchanged.Version != claimed.Version || unchanged.State != writeintent.InFlight {
			t.Fatalf("invalid completion changed the intent: %+v %v", unchanged, err)
		}
		if _, err = store.FindLink(ctx, f.Tenant, target); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("invalid completion left a link: %v", err)
		}
		_, err = store.TransitionIntent(ctx, f.Other, first.ID, claimed.Version,
			docpublish.IntentTransition{Event: writeintent.Acknowledge, Remote: remote("9", 1)}, at(2))
		is(t, "cross-tenant transition", err, shared.ErrNotFound)
		// The event is legal for an in-flight intent; only the stale version makes it a conflict.
		_, err = store.TransitionIntent(ctx, f.Tenant, first.ID, claimed.Version-1,
			docpublish.IntentTransition{Event: writeintent.Ambiguous}, at(2))
		is(t, "stale version", err, shared.ErrConflict)

		done := x.mustMove(claimed, docpublish.IntentTransition{Event: writeintent.Acknowledge, Remote: remote("9", 1)}, at(2))
		if done.State != writeintent.Done || done.RemoteID != "9" || done.RemoteVersion != 1 {
			t.Fatalf("acknowledge: %+v", done)
		}
		created = x.link(target)
		if created.ID != first.ID || created.RemotePageID != "9" || created.RemoteVersion != 1 ||
			created.ContentHash != hash("b") || created.Revision != 1 || created.Scope != docpublish.Engagement ||
			created.ScopeID != f.Engagement || !created.CreatedAt.Equal(at(2)) {
			t.Fatalf("created link: %+v", created)
		}
		byID, err := store.GetLink(ctx, f.Tenant, created.ID)
		if err != nil || !sameLink(byID, created) {
			t.Fatalf("get link: %+v %v", byID, err)
		}
		_, err = store.GetLink(ctx, f.Other, created.ID)
		is(t, "cross-tenant link", err, shared.ErrNotFound)
		_, err = store.FindLink(ctx, f.Other, target)
		is(t, "cross-tenant find", err, shared.ErrNotFound)
		listed, err := store.ListLinks(ctx, f.Tenant, docpublish.Engagement, f.Engagement, 10)
		if err != nil || len(listed) != 1 || !sameLink(listed[0], created) {
			t.Fatalf("list links: %+v %v", listed, err)
		}
		other, err := store.ListLinks(ctx, f.Other, docpublish.Engagement, f.Engagement, 10)
		if err != nil || len(other) != 0 {
			t.Fatalf("another tenant listed the link: %+v %v", other, err)
		}
		_, err = x.move(done, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &epoch}, at(3))
		is(t, "done intent retried", err, shared.ErrConflict)
	})

	t.Run("a replay is still answered after its link exists", func(t *testing.T) {
		replay := first
		replay.ID = "doc-intent-late-replay"
		replay.Marker = docpublish.MarkerFor(replay.ID)
		got, isNew, err := store.CreateOrGetIntent(ctx, f.Tenant, replay)
		if err != nil || isNew || got.ID != first.ID || got.State != writeintent.Done {
			t.Fatalf("late replay: %+v created=%t err=%v", got, isNew, err)
		}
	})

	t.Run("a create for a page that already exists is refused", func(t *testing.T) {
		_, _, err := store.CreateOrGetIntent(ctx, f.Tenant, f.intent("doc-duplicate", target, "k-duplicate", "c"))
		is(t, "second create", err, shared.ErrConflict)
	})

	t.Run("an update must address the link's own target", func(t *testing.T) {
		other := x.publish(x.open(f.intent("doc-project-intent", f.projectTarget("SEC"), "k-project", "d")), remote("20", 1), 10)
		if other.State != writeintent.Done {
			t.Fatalf("project publish: %+v", other)
		}
		projectLink := x.link(f.projectTarget("SEC"))
		if projectLink.Scope != docpublish.Project || projectLink.ScopeID != f.Project {
			t.Fatalf("project link: %+v", projectLink)
		}
		crossed := f.intent("doc-crossed", target, "k-crossed", "c")
		crossed.Action = docpublish.Update
		crossed.LinkID = projectLink.ID
		_, _, err := store.CreateOrGetIntent(ctx, f.Tenant, crossed)
		is(t, "update against another target's link", err, shared.ErrValidation)
	})

	t.Run("republishing moves the link forward and keeps its identity", func(t *testing.T) {
		second := x.publish(x.open(f.update("doc-update-2", created, "k-update-2", "c")), remote("9", 2), 20)
		if second.State != writeintent.Done || second.RemoteVersion != 2 {
			t.Fatalf("update: %+v", second)
		}
		l := x.link(target)
		if l.ID != created.ID || l.RemoteVersion != 2 || l.ContentHash != hash("c") || l.Revision != 2 ||
			!l.CreatedAt.Equal(created.CreatedAt) || !l.UpdatedAt.Equal(at(21)) || l.RemotePageID != "9" {
			t.Fatalf("updated link: %+v", l)
		}

		// A later write that finished first must not be undone by an earlier one finishing late.
		early := x.claim(x.open(f.update("doc-update-early", l, "k-early", "d")), 30)
		late := x.claim(x.open(f.update("doc-update-late", l, "k-late", "e")), 31)
		x.mustMove(late, docpublish.IntentTransition{Event: writeintent.Acknowledge, Remote: remote("9", 5)}, at(32))
		if got := x.link(target); got.RemoteVersion != 5 || got.ContentHash != hash("e") || got.Revision != 3 {
			t.Fatalf("link after the newer write: %+v", got)
		}
		stale := x.mustMove(early, docpublish.IntentTransition{Event: writeintent.Acknowledge, Remote: remote("9", 4)}, at(33))
		if stale.State != writeintent.Done || stale.RemoteVersion != 4 {
			t.Fatalf("the older write is still history: %+v", stale)
		}
		if got := x.link(target); got.RemoteVersion != 5 || got.ContentHash != hash("e") || got.Revision != 3 {
			t.Fatalf("an older write moved the link back: %+v", got)
		}
	})

	t.Run("a completion that contradicts the link is refused whole", func(t *testing.T) {
		l := x.link(target)
		for name, page := range map[string]*docpublish.RemotePage{
			"same version, other content": remote("9", l.RemoteVersion),
			"another page":                remote("77", l.RemoteVersion+1),
		} {
			i := x.claim(x.open(f.update(shared.ID("doc-contra-"+strings.ReplaceAll(name, " ", "-")), l, "k-contra-"+name, "f")), 40)
			_, err := x.move(i, docpublish.IntentTransition{Event: writeintent.Acknowledge, Remote: page}, at(41))
			is(t, name, err, shared.ErrConflict)
			still, err := store.GetIntent(ctx, f.Tenant, i.ID)
			if err != nil || still.State != writeintent.InFlight || still.Version != i.Version {
				t.Fatalf("%s changed the intent: %+v %v", name, still, err)
			}
			if got := x.link(target); !sameLink(got, l) {
				t.Fatalf("%s changed the link: %+v", name, got)
			}
		}
	})

	t.Run("an expired lease is never repeated without reconciliation", func(t *testing.T) {
		container := f.engagementTarget("RECON")
		i := x.open(f.intent("doc-recon", container, "k-recon", "b"))
		lease := at(51)
		i = x.mustMove(i, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, at(50))
		_, err := x.move(i, docpublish.IntentTransition{Event: writeintent.LeaseExpired}, at(50))
		is(t, "premature lease expiry", err, shared.ErrConflict)
		i = x.mustMove(i, docpublish.IntentTransition{Event: writeintent.LeaseExpired}, lease)
		if i.State != writeintent.Uncertain || i.LeaseUntil != nil {
			t.Fatalf("expired lease: %+v", i)
		}
		_, err = x.move(i, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, at(60))
		is(t, "blind retry", err, shared.ErrConflict)
		multiple := x.mustMove(i, docpublish.IntentTransition{Event: writeintent.ReconcileMultiple}, at(61))
		if multiple.State != writeintent.Uncertain || multiple.ErrorCode != "multiple_matches" {
			t.Fatalf("multiple matches: %+v", multiple)
		}
		_, err = x.move(multiple, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, at(62))
		is(t, "retry after multiple matches", err, shared.ErrConflict)
		found := x.mustMove(multiple, docpublish.IntentTransition{Event: writeintent.ReconcileFound, Remote: remote("31", 1)}, at(63))
		if found.State != writeintent.Done || found.ErrorCode != "" {
			t.Fatalf("reconcile found: %+v", found)
		}
		if l := x.link(container); l.RemotePageID != "31" || l.ID != i.ID {
			t.Fatalf("reconciled link: %+v", l)
		}
	})

	t.Run("a reconciled absence returns to pending and may be written again", func(t *testing.T) {
		container := f.engagementTarget("ABSENT")
		i := x.open(f.intent("doc-absent", container, "k-absent", "b"))
		lease := at(71)
		i = x.mustMove(i, docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, at(70))
		i = x.mustMove(i, docpublish.IntentTransition{Event: writeintent.Ambiguous}, at(72))
		i = x.mustMove(i, docpublish.IntentTransition{Event: writeintent.ReconcileAbsent}, at(73))
		if i.State != writeintent.Pending || i.Attempts != 1 {
			t.Fatalf("reconcile absent: %+v", i)
		}
		i = x.publish(i, remote("41", 1), 80)
		if i.Attempts != 2 || i.State != writeintent.Done {
			t.Fatalf("second attempt: %+v", i)
		}
	})

	t.Run("a rejection carries a stable classification", func(t *testing.T) {
		container := f.engagementTarget("REJECT")
		i := x.claim(x.open(f.intent("doc-rejected", container, "k-rejected", "b")), 90)
		_, err := x.move(i, docpublish.IntentTransition{Event: writeintent.Reject}, at(91))
		is(t, "rejection without a code", err, shared.ErrValidation)
		failed := x.mustMove(i, docpublish.IntentTransition{Event: writeintent.Reject, ErrorCode: "provider_rejected"}, at(91))
		if failed.State != writeintent.Failed || failed.ErrorCode != "provider_rejected" {
			t.Fatalf("rejection: %+v", failed)
		}
		pending := x.mustMove(failed, docpublish.IntentTransition{Event: writeintent.RetryFailed}, at(92))
		if pending.State != writeintent.Pending || pending.ErrorCode != "" {
			t.Fatalf("retry: %+v", pending)
		}
	})

	t.Run("listing is bounded and newest first", func(t *testing.T) {
		for _, limit := range []int{0, -1, docpublish.MaxListLimit + 1} {
			_, err := store.ListLinks(ctx, f.Tenant, docpublish.Engagement, f.Engagement, limit)
			is(t, "bad limit", err, shared.ErrValidation)
		}
		_, err := store.ListLinks(ctx, f.Tenant, "folder", f.Engagement, 10)
		is(t, "unknown scope", err, shared.ErrValidation)
		all, err := store.ListLinks(ctx, f.Tenant, docpublish.Engagement, f.Engagement, docpublish.MaxListLimit)
		if err != nil || len(all) < 3 {
			t.Fatalf("expected several links: %+v %v", all, err)
		}
		for n := 1; n < len(all); n++ {
			if all[n-1].CreatedAt.Before(all[n].CreatedAt) {
				t.Fatalf("not newest first: %+v", all)
			}
		}
		one, err := store.ListLinks(ctx, f.Tenant, docpublish.Engagement, f.Engagement, 1)
		if err != nil || len(one) != 1 || one[0].ID != all[0].ID {
			t.Fatalf("limit: %+v %v", one, err)
		}
		projects, err := store.ListLinks(ctx, f.Tenant, docpublish.Project, f.Project, 10)
		if err != nil || len(projects) != 1 || projects[0].Scope != docpublish.Project {
			t.Fatalf("project scope: %+v %v", projects, err)
		}
	})

	t.Run("a stored value is a copy", func(t *testing.T) {
		inFlight := x.claim(x.open(f.intent("doc-alias", f.engagementTarget("ALIAS"), "k-alias", "b")), 100)
		*inFlight.LeaseUntil = epoch
		again, err := store.GetIntent(ctx, f.Tenant, inFlight.ID)
		if err != nil || again.LeaseUntil == nil || !again.LeaseUntil.After(at(100)) {
			t.Fatalf("lease aliased its caller: %+v %v", again, err)
		}
	})
}

// ConcurrentReplay proves a request key can be won by just one caller, even when many
// requests generate different IDs before attempting to persist.
func ConcurrentReplay(t *testing.T, store ports.DocumentStore, f Fixture) {
	t.Helper()
	ctx := context.Background()
	type reply struct {
		id      shared.ID
		created bool
		err     error
	}
	const workers = 12
	results := make(chan reply, workers)
	var wg sync.WaitGroup
	for n := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := shared.ID("doc-race-" + string(rune('a'+n)))
			got, created, err := store.CreateOrGetIntent(ctx, f.Tenant, f.intent(id, f.engagementTarget("RACE-REPLAY"), "race-request", "b"))
			results <- reply{id: got.ID, created: created, err: err}
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	var winner shared.ID
	for r := range results {
		if r.err != nil {
			t.Fatalf("parallel retry: %v", r.err)
		}
		if r.created {
			winners++
		}
		if winner.IsZero() {
			winner = r.id
		} else if winner != r.id {
			t.Fatalf("duplicate durable intents: %s != %s", winner, r.id)
		}
	}
	if winners != 1 {
		t.Fatalf("created %d intents, expected 1", winners)
	}
}

// ConcurrentClaim proves a single version can be claimed by only one worker.
func ConcurrentClaim(t *testing.T, store ports.DocumentStore, f Fixture) {
	t.Helper()
	ctx := context.Background()
	x := h{t: t, store: store, f: f}
	i := x.open(f.intent("doc-claim", f.engagementTarget("RACE-CLAIM"), "claim-race", "b"))
	const workers = 12
	results := make(chan error, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			<-start
			lease := at(1).Add(time.Hour)
			_, err := store.TransitionIntent(ctx, f.Tenant, i.ID, 1,
				docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, at(1))
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
	got, err := store.GetIntent(ctx, f.Tenant, i.ID)
	if err != nil || winners != 1 || got.Attempts != 1 || got.Version != 2 || got.State != writeintent.InFlight {
		t.Fatalf("claim race winners=%d intent=%+v error=%v", winners, got, err)
	}
}

// ConcurrentCompletionConflict proves that two creates for one target cannot both leave a
// link: the loser's transition is refused whole and its intent is left uncertain, so the
// intent transition and its link write are one atomic unit in both adapters.
func ConcurrentCompletionConflict(t *testing.T, store ports.DocumentStore, f Fixture) {
	t.Helper()
	ctx := context.Background()
	x := h{t: t, store: store, f: f}
	target := f.engagementTarget("RACE-COMPLETE")
	ids := []shared.ID{"doc-completion-a", "doc-completion-b"}
	for _, id := range ids {
		i := x.open(f.intent(id, target, "completion-"+id.String(), "b"))
		i = x.claim(i, 1)
		x.mustMove(i, docpublish.IntentTransition{Event: writeintent.Ambiguous}, at(3))
	}
	results := make(chan error, len(ids))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Go(func() {
			<-start
			_, err := store.TransitionIntent(ctx, f.Tenant, id, 3,
				docpublish.IntentTransition{Event: writeintent.ReconcileFound, Remote: remote("page-"+id.String(), 1)}, at(4))
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
			t.Fatalf("conflicting completion: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("conflicting completions had %d winners", winners)
	}
	links, err := store.ListLinks(ctx, f.Tenant, docpublish.Engagement, f.Engagement, docpublish.MaxListLimit)
	count := 0
	for _, l := range links {
		if l.Container == "RACE-COMPLETE" {
			count++
		}
	}
	if err != nil || count != 1 {
		t.Fatalf("conflicting completion links: %d %v", count, err)
	}
	done, uncertain := 0, 0
	for _, id := range ids {
		i, getErr := store.GetIntent(ctx, f.Tenant, id)
		if getErr != nil {
			t.Fatal(getErr)
		}
		switch i.State {
		case writeintent.Done:
			done++
		case writeintent.Uncertain:
			if i.Version != 3 {
				t.Fatalf("conflicted intent was partially updated: %+v", i)
			}
			uncertain++
		default:
			t.Fatalf("unexpected completion state: %+v", i)
		}
	}
	if done != 1 || uncertain != 1 {
		t.Fatalf("completion states done=%d uncertain=%d", done, uncertain)
	}
}

// ConcurrentUpdateCompletion proves two republishes that finish together leave the link at
// the newest remote version whichever order they commit in, and that both intents finish.
func ConcurrentUpdateCompletion(t *testing.T, store ports.DocumentStore, f Fixture) {
	t.Helper()
	ctx := context.Background()
	x := h{t: t, store: store, f: f}
	target := f.engagementTarget("RACE-UPDATE")
	base := x.publish(x.open(f.intent("doc-update-base", target, "update-base", "b")), remote("66", 1), 1)
	if base.State != writeintent.Done {
		t.Fatalf("base publish: %+v", base)
	}
	link := x.link(target)
	type writer struct {
		id      shared.ID
		version int
		content string
	}
	writers := []writer{{"doc-update-x", 2, "c"}, {"doc-update-y", 3, "d"}}
	claimed := map[shared.ID]docpublish.Intent{}
	for _, w := range writers {
		claimed[w.id] = x.claim(x.open(f.update(w.id, link, "key-"+w.id.String(), w.content)), 10)
	}
	results := make(chan error, len(writers))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, w := range writers {
		wg.Go(func() {
			<-start
			_, err := store.TransitionIntent(ctx, f.Tenant, w.id, claimed[w.id].Version,
				docpublish.IntentTransition{Event: writeintent.Acknowledge, Remote: remote("66", w.version)}, at(20))
			results <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("racing republish: %v", err)
		}
	}
	got := x.link(target)
	if got.RemoteVersion != 3 || got.ContentHash != hash("d") || got.RemotePageID != "66" {
		t.Fatalf("link did not settle on the newest write: %+v", got)
	}
	if got.Revision < 2 || got.Revision > 3 {
		t.Fatalf("link revision %d is not one write per applied completion", got.Revision)
	}
	for _, w := range writers {
		i, err := store.GetIntent(ctx, f.Tenant, w.id)
		if err != nil || i.State != writeintent.Done {
			t.Fatalf("republish %s: %+v %v", w.id, i, err)
		}
	}
}

// CanceledContext ensures no adapter performs work after cancellation.
func CanceledContext(t *testing.T, store ports.DocumentStore, f Fixture) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	target := f.engagementTarget("CANCEL")
	intent := f.intent("doc-canceled", target, "canceled", "b")
	checks := []struct {
		name string
		run  func() error
	}{
		{"get link", func() error { _, err := store.GetLink(ctx, f.Tenant, "doc-link"); return err }},
		{"find link", func() error { _, err := store.FindLink(ctx, f.Tenant, target); return err }},
		{"list links", func() error {
			_, err := store.ListLinks(ctx, f.Tenant, docpublish.Engagement, f.Engagement, 10)
			return err
		}},
		{"create intent", func() error { _, _, err := store.CreateOrGetIntent(ctx, f.Tenant, intent); return err }},
		{"get intent", func() error { _, err := store.GetIntent(ctx, f.Tenant, intent.ID); return err }},
		{"transition intent", func() error {
			_, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 1,
				docpublish.IntentTransition{Event: writeintent.Acknowledge}, epoch)
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
