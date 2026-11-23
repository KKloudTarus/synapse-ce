package evidence

import (
	"context"
	"errors"
	"testing"

	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAnchoringWaitsForSuccessfulCommit(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "commit"}[committed], func(t *testing.T) {
			svc, _, _ := newVault(t, nil)
			tsa, timestamps := &stubTSA{}, newTSStore()
			svc.SetTimestamper(tsa, timestamps)
			rollback := errors.New("commit failed")
			err := AnchorAfterCommit(context.Background(), func(ctx context.Context) error {
				if _, err := svc.Seal(ctx, "eng", "admission", []byte("admit"), "op"); err != nil {
					return err
				}
				if _, err := svc.SealWithID(ctx, "consumed", "eng", "consumption", []byte("consume"), "op"); err != nil {
					return err
				}
				if tsa.calls != 0 || len(timestamps.m) != 0 {
					t.Fatal("uncommitted head was anchored")
				}
				if !committed {
					return rollback
				}
				return nil
			})
			if committed {
				if err != nil || tsa.calls != 2 || len(timestamps.m) != 2 {
					t.Fatalf("committed anchors: calls=%d records=%d err=%v", tsa.calls, len(timestamps.m), err)
				}
			} else if !errors.Is(err, rollback) || tsa.calls != 0 || len(timestamps.m) != 0 {
				t.Fatal("rollback retained an out-of-band anchor")
			}
		})
	}
}

type indexedEvidenceStore struct {
	*memStore
	lookups int
}

func (s *indexedEvidenceStore) LookupSealedByID(_ context.Context, eng, id shared.ID) (evdom.Evidence, bool, error) {
	s.lookups++
	for _, item := range s.items[eng] {
		if item.ID == id {
			return item, true, nil
		}
	}
	return evdom.Evidence{}, false, nil
}
func (*indexedEvidenceStore) ListByEngagement(context.Context, shared.ID) ([]evdom.Evidence, error) {
	return nil, errors.New("full ledger read forbidden in reserved seal")
}
func TestReservedSealUsesIndexedLookup(t *testing.T) {
	svc, _, _ := newVault(t, nil)
	store := &indexedEvidenceStore{memStore: newMemStore()}
	svc.store = store
	first, err := svc.SealWithID(context.Background(), "reserved", "eng", "custody", []byte("first"), "op")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.SealWithID(context.Background(), "reserved", "eng", "custody", []byte("retry"), "op")
	if err != nil || first.Hash != second.Hash || store.lookups != 3 {
		t.Fatalf("indexed reserved seal: lookups=%d err=%v", store.lookups, err)
	}
}
