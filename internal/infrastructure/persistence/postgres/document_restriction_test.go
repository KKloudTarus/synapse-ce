package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/jackc/pgx/v5"
)

func TestDocumentRestrictionPostgresClaimsAreBoundedFairAndFenced(t *testing.T) {
	ctx := context.Background()
	dsn := testDSN(t)
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
	at := time.Date(2026, 10, 18, 7, 0, 0, 0, time.UTC)
	err = WithTenant(ctx, pool, "doc-a", func(tx pgx.Tx) error {
		for n := 0; n < 6; n++ {
			_, err := tx.Exec(ctx, `INSERT INTO document_links(id,tenant_id,integration_id,source_kind,source_ref,engagement_id,container,remote_page_id,remote_version,remote_url,content_hash,revision,created_at,updated_at) VALUES($1,'doc-a','doc-integration-a','engagement_report',$1,'doc-engagement-a','SEC',$1,1,'https://wiki.example/page',repeat('a',64),1,$2,$2)`, fmt.Sprintf("restriction-link-%d", n), at)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan []docpublish.Link, 2)
	failures := make(chan error, 2)
	for n := 0; n < 2; n++ {
		wg.Go(func() {
			links, err := store.ClaimDocumentRestrictionChecks(ctx, "doc-a", 2, at)
			results <- links
			failures <- err
		})
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := map[shared.ID]bool{}
	var first docpublish.Link
	for links := range results {
		if len(links) != 2 {
			t.Fatalf("claim size=%d", len(links))
		}
		for _, link := range links {
			if seen[link.ID] {
				t.Fatal("concurrent workers claimed same link")
			}
			seen[link.ID] = true
			first = link
		}
	}
	next, err := store.ClaimDocumentRestrictionChecks(ctx, "doc-a", 2, at)
	if err != nil || len(next) != 2 {
		t.Fatalf("remaining claim=%d %v", len(next), err)
	}
	for _, link := range next {
		if seen[link.ID] {
			t.Fatal("unresolved claim starved remaining link")
		}
	}
	if foreign, err := store.ClaimDocumentRestrictionChecks(ctx, "doc-b", 2, at); err != nil || len(foreign) != 0 {
		t.Fatalf("cross-tenant claim=%d %v", len(foreign), err)
	}
	if err = store.SaveDocumentRestrictionCheck(ctx, "doc-a", first, "restriction_lost", at, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	current, err := store.GetLink(ctx, "doc-a", first.ID)
	if err != nil || current.RestrictionStatus != "restriction_lost" || current.Revision != first.Revision {
		t.Fatalf("observation corrupted publication: %+v %v", current, err)
	}
	if err = WithTenant(ctx, pool, "doc-a", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE document_links SET revision=revision+1 WHERE tenant_id='doc-a' AND id=$1`, first.ID.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.SaveDocumentRestrictionCheck(ctx, "doc-a", first, "verified", at, at.Add(time.Hour)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("concurrent republish was not fenced: %v", err)
	}
	if err = store.SaveDocumentRestrictionCheck(ctx, "doc-b", first, "verified", at, at.Add(time.Hour)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("foreign observation accepted: %v", err)
	}
}
