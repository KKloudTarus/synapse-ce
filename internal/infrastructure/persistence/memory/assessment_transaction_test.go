package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
)

func TestAssessmentTransactionPublishesJobsOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	queue := NewJobQueue(idgen.RandomID{}, time.Now)
	tx := NewTenantTransactionRunner()
	failure := errors.New("audit unavailable")
	for _, fail := range []bool{true, false} {
		err := tx.Run(ctx, "tenant", func(txCtx context.Context) error {
			if _, err := queue.Enqueue(txCtx, "assessment-comparison", []byte(`{}`)); err != nil {
				return err
			}
			job, err := queue.Claim(ctx, time.Minute)
			if err != nil || job != nil {
				t.Fatalf("uncommitted job visible: %+v err=%v", job, err)
			}
			if fail {
				return failure
			}
			return nil
		})
		if fail && !errors.Is(err, failure) || !fail && err != nil {
			t.Fatal(err)
		}
		job, err := queue.Claim(ctx, time.Minute)
		if err != nil || fail && job != nil || !fail && job == nil {
			t.Fatalf("post-transaction visibility (fail=%v): %+v err=%v", fail, job, err)
		}
	}
}

func TestAssessmentTransactionRollsBackWithoutAliasingEngagement(t *testing.T) {
	ctx := context.Background()
	repo := NewEngagementRepository()
	item, err := engagement.New("assessment", "tenant", "Initial", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, item); err != nil {
		t.Fatal(err)
	}
	item.Name = "caller mutation"
	if err := NewTenantTransactionRunner().Run(ctx, "tenant", func(txCtx context.Context) error {
		got, err := repo.GetByIDInTenant(txCtx, "tenant", item.ID)
		if err != nil {
			return err
		}
		got.Name = "uncommitted"
		if err := repo.Update(txCtx, got); err != nil {
			return err
		}
		return shared.ErrConflict
	}); !errors.Is(err, shared.ErrConflict) {
		t.Fatal(err)
	}
	got, err := repo.GetByIDInTenant(ctx, "tenant", item.ID)
	if err != nil || got.Name != "Initial" {
		t.Fatalf("rollback aliased: %+v err=%v", got, err)
	}
}
