package sca

import (
	"context"
	"errors"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type fakeScannedStore struct {
	marks []scannedMark
	err   error
}

type scannedMark struct {
	tenant shared.ID
	digest string
}

func (f *fakeScannedStore) MarkScanned(_ context.Context, tenant shared.ID, digest string, _ time.Time) error {
	f.marks = append(f.marks, scannedMark{tenant, digest})
	return f.err
}
func (f *fakeScannedStore) ScannedDigests(context.Context, shared.ID) (map[string]bool, error) {
	return nil, nil
}

func imageResult(digest string) *ScanResult {
	return &ScanResult{Image: &sbom.ImageInfo{Reference: "reg/x:1", Digest: digest}}
}

func TestRecordScannedImageMarksDigestUnderTenant(t *testing.T) {
	store := &fakeScannedStore{}
	s := &Service{
		scannedImages: store,
		engagements:   &fakeEngRepo{eng: &engdom.Engagement{TenantID: "tenant-x"}},
		clock:         fakeClock{t: time.Unix(1700000000, 0).UTC()},
	}
	s.recordScannedImage(context.Background(), "eng-1", imageResult("sha256:aaa"))
	if len(store.marks) != 1 || store.marks[0].digest != "sha256:aaa" || store.marks[0].tenant != "tenant-x" {
		t.Fatalf("expected one mark for sha256:aaa under tenant-x, got %+v", store.marks)
	}
}

func TestRecordScannedImageNoOps(t *testing.T) {
	cases := []struct {
		name      string
		withStore bool
		result    *ScanResult
	}{
		{"no recorder", false, imageResult("sha256:aaa")},
		{"nil result", true, nil},
		{"non-image scan", true, &ScanResult{}},
		{"empty digest", true, imageResult("")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var store *fakeScannedStore
			s := &Service{
				engagements: &fakeEngRepo{eng: &engdom.Engagement{TenantID: "t"}},
				clock:       fakeClock{t: time.Unix(0, 0)},
			}
			if c.withStore {
				store = &fakeScannedStore{}
				s.scannedImages = store
			}
			s.recordScannedImage(context.Background(), "eng-1", c.result) // must not panic
			if store != nil && len(store.marks) != 0 {
				t.Fatalf("%s: expected no mark, got %+v", c.name, store.marks)
			}
		})
	}
}

func TestRecordScannedImageBestEffortOnErrors(t *testing.T) {
	// An engagement-lookup failure records nothing but does not panic/propagate.
	s := &Service{
		scannedImages: &fakeScannedStore{},
		engagements:   &fakeEngRepo{err: errors.New("not found")},
		clock:         fakeClock{t: time.Unix(0, 0)},
	}
	s.recordScannedImage(context.Background(), "eng-1", imageResult("sha256:aaa"))

	// A store write failure is swallowed (best-effort — a missed record becomes a later conservative gap).
	store := &fakeScannedStore{err: errors.New("db down")}
	s2 := &Service{
		scannedImages: store,
		engagements:   &fakeEngRepo{eng: &engdom.Engagement{TenantID: "t"}},
		clock:         fakeClock{t: time.Unix(0, 0)},
	}
	s2.recordScannedImage(context.Background(), "eng-1", imageResult("sha256:aaa")) // must not panic/propagate
	if len(store.marks) != 1 {
		t.Fatalf("MarkScanned should still have been attempted, got %+v", store.marks)
	}
}
