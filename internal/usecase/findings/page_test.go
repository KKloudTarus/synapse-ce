package findings

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type pageRepo struct {
	fakeRepo
	page ports.FindingPage
}

func (r *pageRepo) ListFindingPage(context.Context, shared.ID, shared.ID, int) (ports.FindingPage, error) {
	return r.page, nil
}

func TestListPageBoundsAndFailsClosedWithoutPageReader(t *testing.T) {
	unsupported := NewService(&fakeRepo{}, nil, nil, nil, nil, nil)
	if _, err := unsupported.ListPage(context.Background(), "engagement", "", 50); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unsupported page reader error = %v, want validation", err)
	}

	repository := &pageRepo{page: ports.FindingPage{Items: []finding.Finding{{ID: "finding-a", EngagementID: "engagement", Status: finding.StatusOpen}}}}
	service := NewService(repository, nil, nil, nil, nil, nil)
	page, err := service.ListPage(context.Background(), "engagement", "", 0)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("default page = %+v, err=%v", page, err)
	}
	if _, err := service.ListPage(context.Background(), "engagement", "", 101); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized page error = %v, want validation", err)
	}
}

func TestGetRejectsEmptyScope(t *testing.T) {
	service := NewService(&fakeRepo{}, nil, nil, nil, nil, nil)
	if _, err := service.Get(context.Background(), "", "finding"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("Get empty engagement error = %v, want validation", err)
	}
}
