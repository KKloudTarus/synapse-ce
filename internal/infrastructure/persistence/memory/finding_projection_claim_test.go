package memory

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestFindingProjectionClaimConcurrentModes(t *testing.T) {
	repo := NewFindingRepository()
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, mode := range []ports.FindingProjectionMode{ports.FindingProjectionSAST, ports.FindingProjectionDAST} {
		wg.Add(1)
		go func(mode ports.FindingProjectionMode) {
			defer wg.Done()
			<-start
			errs <- repo.ClaimFindingProjection(context.Background(), "default", "eng-1", "judgment-1", mode)
		}(mode)
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
			t.Fatalf("claim: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("claims: %d succeeded, %d conflicted; want 1 each", succeeded, conflicted)
	}
}

func TestFindingProjectionClaimSameModeRetries(t *testing.T) {
	repo := NewFindingRepository()
	ctx := context.Background()
	if err := repo.ClaimFindingProjection(ctx, "default", "eng-1", "judgment-1", ports.FindingProjectionSAST); err != nil {
		t.Fatal(err)
	}
	if err := repo.ClaimFindingProjection(ctx, "default", "eng-1", "judgment-1", ports.FindingProjectionSAST); err != nil {
		t.Fatalf("same-mode retry: %v", err)
	}
}
