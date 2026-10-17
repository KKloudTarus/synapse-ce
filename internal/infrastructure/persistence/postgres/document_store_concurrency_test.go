package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
)

// documentLinkQueryBarrier pauses a retry after its initial request-key lookup, so
// another connection can finish publishing before the retry checks for a link.
type documentLinkQueryBarrier struct {
	arrived chan struct{}
	release chan struct{}
}

func (b *documentLinkQueryBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "FROM document_links") {
		select {
		case b.arrived <- struct{}{}:
		default:
		}
		select {
		case <-b.release:
		case <-ctx.Done():
		}
	}
	return ctx
}

func (*documentLinkQueryBarrier) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestDocumentStoreReplayRacingCompletion(t *testing.T) {
	for _, changed := range []bool{false, true} {
		name := "identical command"
		if changed {
			name = "different content"
		}
		t.Run(name, func(t *testing.T) {
			dsn := testDSN(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := MigrateLocked(ctx, dsn); err != nil {
				t.Fatal(err)
			}
			pool, err := Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			seedDocumentTenants(t, ctx, pool)
			store, err := NewDocumentStore(pool)
			if err != nil {
				t.Fatal(err)
			}
			barrier := &documentLinkQueryBarrier{arrived: make(chan struct{}, 1), release: make(chan struct{})}
			config, err := pgxpool.ParseConfig(dsn)
			if err != nil {
				t.Fatal(err)
			}
			config.ConnConfig.Tracer = barrier
			retryPool, err := pgxpool.NewWithConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); retryPool.Close() }()
			retryStore, err := NewDocumentStore(retryPool)
			if err != nil {
				t.Fatal(err)
			}
			f := documentFixture()
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			intent := docpublish.Intent{ID: "doc-replay-completion", TenantID: f.Tenant,
				Target: docpublish.Target{IntegrationID: f.Integration, SourceKind: docpublish.EngagementReport,
					SourceRef: "engagement-report", Scope: docpublish.Engagement, ScopeID: f.Engagement, Container: "REPLAY"},
				Action: docpublish.Create, RequestKey: "replay-completion", PayloadDigest: strings.Repeat("a", 64),
				ContentHash: strings.Repeat("b", 64), Marker: docpublish.MarkerFor("doc-replay-completion"),
				State: writeintent.Pending, Version: 1, CreatedAt: now, UpdatedAt: now}
			retry := intent
			retry.ID, retry.Marker = "doc-concurrent-replay", docpublish.MarkerFor("doc-concurrent-replay")
			if changed {
				retry.ContentHash = strings.Repeat("c", 64)
			}
			type reply struct {
				intent  docpublish.Intent
				created bool
				err     error
			}
			result := make(chan reply, 1)
			go func() {
				i, created, e := retryStore.CreateOrGetIntent(ctx, f.Tenant, retry)
				result <- reply{i, created, e}
			}()
			select {
			case <-barrier.arrived:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if _, _, err = store.CreateOrGetIntent(ctx, f.Tenant, intent); err != nil {
				t.Fatal(err)
			}
			lease := now.Add(time.Hour)
			if _, err = store.TransitionIntent(ctx, f.Tenant, intent.ID, 1,
				docpublish.IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			done, err := store.TransitionIntent(ctx, f.Tenant, intent.ID, 2,
				docpublish.IntentTransition{Event: writeintent.Acknowledge,
					Remote: &docpublish.RemotePage{ID: "9", Version: 1, URL: "https://wiki.example/pages/9"}}, now.Add(2*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			close(barrier.release)
			select {
			case got := <-result:
				if changed {
					if !errors.Is(got.err, shared.ErrConflict) || got.created {
						t.Fatalf("changed replay: %+v", got)
					}
				} else if got.err != nil || got.created || got.intent.ID != done.ID || got.intent.State != writeintent.Done || got.intent.Version != done.Version {
					t.Fatalf("identical replay did not return completed intent: %+v", got)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			link, err := store.FindLink(ctx, f.Tenant, intent.Target)
			if err != nil || link.ContentHash != intent.ContentHash || link.RemoteVersion != 1 || link.Revision != 1 {
				t.Fatalf("replay changed the completed link: %+v %v", link, err)
			}
			stored, err := store.GetIntent(ctx, f.Tenant, intent.ID)
			if err != nil || stored.State != done.State || stored.Version != done.Version || stored.ContentHash != done.ContentHash {
				t.Fatalf("replay changed the completed intent: %+v %v", stored, err)
			}
		})
	}
}
