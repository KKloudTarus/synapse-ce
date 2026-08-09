package findings

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

func TestConcurrentCapSASTProjectionSelectsOneMode(t *testing.T) {
	repo := memory.NewFindingRepository()
	svc := newSvc(repo, &fakeComments{}, &fakeAudit{})
	j := confirmedSAST()
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, record := range []func(context.Context, string, judgment.Judgment) error{svc.RecordConfirmedSAST, svc.RecordConfirmedDAST} {
		wg.Add(1)
		go func(record func(context.Context, string, judgment.Judgment) error) {
			defer wg.Done()
			<-start
			errs <- record(context.Background(), "human:bob", j)
		}(record)
	}
	close(start)
	wg.Wait()
	close(errs)

	var succeeded, conflicted int
	for err := range errs {
		if err == nil {
			succeeded++
		} else if errors.Is(err, shared.ErrConflict) {
			conflicted++
		} else {
			t.Fatalf("projection: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("projections: %d succeeded, %d conflicted; want 1 each", succeeded, conflicted)
	}
	stored, err := repo.ListByEngagement(context.Background(), j.EngagementID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || (stored[0].Kind != finding.KindSAST && stored[0].Kind != finding.KindDAST) {
		t.Fatalf("stored projections = %+v; want exactly one SAST or DAST finding", stored)
	}
}

func TestCapSASTProjectionSameModeRetry(t *testing.T) {
	repo := memory.NewFindingRepository()
	svc := newSvc(repo, &fakeComments{}, &fakeAudit{})
	j := confirmedSAST()
	if err := svc.RecordConfirmedSAST(context.Background(), "human:bob", j); err != nil {
		t.Fatal(err)
	}
	if err := svc.RecordConfirmedSAST(context.Background(), "human:bob", j); err != nil {
		t.Fatalf("same-mode retry: %v", err)
	}
	stored, err := repo.ListByEngagement(context.Background(), j.EngagementID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].Kind != finding.KindSAST {
		t.Fatalf("stored projections = %+v; want one SAST finding", stored)
	}
}

type failOnceProjectionRepo struct {
	*fakeRepo
	fail bool
}

func (r *failOnceProjectionRepo) Upsert(ctx context.Context, fs []finding.Finding) error {
	if r.fail {
		r.fail = false
		return errors.New("transient upsert failure")
	}
	return r.fakeRepo.Upsert(ctx, fs)
}

func TestCapSASTProjectionRetriesAfterUpsertFailure(t *testing.T) {
	repo := &failOnceProjectionRepo{fakeRepo: &fakeRepo{}, fail: true}
	svc := newSvc(repo, &fakeComments{}, &fakeAudit{})
	j := confirmedSAST()
	if err := svc.RecordConfirmedSAST(context.Background(), "human:bob", j); err == nil {
		t.Fatal("first upsert must fail")
	}
	if err := svc.RecordConfirmedSAST(context.Background(), "human:bob", j); err != nil {
		t.Fatalf("same-mode retry after failed upsert: %v", err)
	}
	if len(repo.upserted) != 1 || repo.upserted[0].Kind != finding.KindSAST {
		t.Fatalf("persisted projections = %+v; want one SAST finding", repo.upserted)
	}
}
