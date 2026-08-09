package findings

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type projectionAttributor struct {
	asset     shared.ID
	inherited shared.ID
	err       error
	recordErr error
	recorded  []shared.ID
}

func (a *projectionAttributor) ValidateAsset(_ context.Context, _, assetID shared.ID) error {
	if a.err != nil {
		return a.err
	}
	if assetID != a.asset {
		return shared.ErrNotFound
	}
	return nil
}

func (a *projectionAttributor) Record(_ context.Context, _, assetID, _, _ shared.ID, _ asset.EdgeConfidence, findingIDs []shared.ID) error {
	if assetID != a.asset {
		return shared.ErrNotFound
	}
	if a.recordErr != nil {
		err := a.recordErr
		a.recordErr = nil
		return err
	}
	a.recorded = append(a.recorded, findingIDs...)
	return nil
}

func (a *projectionAttributor) RecordTargets(_ context.Context, _ shared.ID, assetID, _, _ shared.ID, _ asset.EdgeConfidence, targets []attackpath.FindingTarget) error {
	if assetID != a.asset {
		return shared.ErrNotFound
	}
	for _, target := range targets {
		a.recorded = append(a.recorded, target.ID)
	}
	return nil
}

func (a *projectionAttributor) InheritedAssetID(_ context.Context, _ shared.ID, _ []shared.ID) (shared.ID, error) {
	return a.inherited, a.err
}

func TestCreateAttributedRetryUsesCanonicalFinding(t *testing.T) {
	repo := &fakeRepo{}
	svc := newSvc(repo, &fakeComments{}, &fakeAudit{})
	a := &projectionAttributor{asset: "asset-1"}
	svc.SetAttributor(a)
	first, err := svc.CreateAttributed(context.Background(), "human:alice", "eng-1", "asset-1", finding.ManualInput{Title: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	repo.list = append([]finding.Finding(nil), repo.upserted...)
	second, err := svc.CreateAttributed(context.Background(), "human:alice", "eng-1", "asset-1", finding.ManualInput{Title: "manual"})
	if err != nil || second.ID != first.ID || len(repo.upserted) != 1 {
		t.Fatalf("retry = %+v, %v, upserts=%d", second, err, len(repo.upserted))
	}
}

func TestVerifiedProjectionRetryUsesCanonicalFinding(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		record func(*Service, context.Context, string, judgment.Judgment) error
		j      judgment.Judgment
	}{
		{"threat", (*Service).RecordConfirmedThreat, confirmedThreat()},
		{"sast", (*Service).RecordConfirmedSAST, confirmedSAST()},
		{"dast", (*Service).RecordConfirmedDAST, confirmedSAST()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepo{}
			a := &projectionAttributor{asset: "asset-1", recordErr: errors.New("attribution unavailable")}
			audit := &fakeAudit{}
			svc := newSvc(repo, &fakeComments{}, audit)
			svc.SetAttributor(a)
			if tc.name == "threat" {
				tc.j.Claim = judgment.ThreatClaim{Category: judgment.InfoDisclosure, Asset: "pii", AssetID: "asset-1"}
			} else {
				tc.j.Claim = judgment.SASTClaim{CWE: "CWE-89", Location: "app/dao.Find", Rule: "taint-sqli", AssetID: "asset-1"}
			}

			if err := tc.record(svc, ctx, "human:bob", tc.j); err == nil {
				t.Fatal("first projection must report its persisted attribution repair")
			} else {
				var partial *ports.PartialWriteError
				if !errors.As(err, &partial) {
					t.Fatalf("want partial write error, got %v", err)
				}
			}
			persisted := repo.upserted[0]
			persisted.ID = "canonical-" + shared.ID(tc.name)
			repo.list = []finding.Finding{persisted}

			if err := tc.record(svc, ctx, "human:bob", tc.j); err != nil {
				t.Fatalf("retry projection: %v", err)
			}
			if len(a.recorded) != 1 || a.recorded[0] != persisted.ID {
				t.Fatalf("attribution must bind canonical persisted id %q, got %v", persisted.ID, a.recorded)
			}
			if len(audit.entries) != 1 {
				t.Fatalf("successful replay appends one promotion audit after failed attribution, got %d", len(audit.entries))
			}
		})
	}
}

// Retries append their own promotion audit entry: the audit log is append-only and this use case has no
// audit lookup port with which to suppress a replay record.
func TestVerifiedProjectionSuccessfulRetryAuditsReplay(t *testing.T) {
	repo := &fakeRepo{}
	audit := &fakeAudit{}
	svc := newSvc(repo, &fakeComments{}, audit)
	j := confirmedSAST()
	if err := svc.RecordConfirmedSAST(context.Background(), "human:bob", j); err != nil {
		t.Fatal(err)
	}
	if err := svc.RecordConfirmedSAST(context.Background(), "human:bob", j); err != nil {
		t.Fatal(err)
	}
	if len(audit.entries) != 2 {
		t.Fatalf("successful replay must append a promotion audit entry, got %d", len(audit.entries))
	}
}

func TestVerifiedProjectionCanonicalLookupFailureReportsCandidate(t *testing.T) {
	repo := &fakeRepo{listErr: errors.New("lookup unavailable")}
	svc := newSvc(repo, &fakeComments{}, &fakeAudit{})
	j := confirmedThreat()
	if err := svc.RecordConfirmedThreat(context.Background(), "human:bob", j); err == nil {
		t.Fatal("want partial write error")
	} else {
		var partial *ports.PartialWriteError
		if !errors.As(err, &partial) || len(partial.IDs) != 1 || partial.IDs[0] != repo.upserted[0].ID {
			t.Fatalf("partial write must name candidate %q, got %+v", repo.upserted[0].ID, partial)
		}
	}
}

func TestVerifiedProjectionRejectsCrossModeReplay(t *testing.T) {
	ctx := context.Background()
	j := confirmedSAST()
	for _, tc := range []struct {
		name  string
		first func(*Service, context.Context, string, judgment.Judgment) error
		next  func(*Service, context.Context, string, judgment.Judgment) error
	}{
		{"static then runtime", (*Service).RecordConfirmedSAST, (*Service).RecordConfirmedDAST},
		{"runtime then static", (*Service).RecordConfirmedDAST, (*Service).RecordConfirmedSAST},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepo{}
			svc := newSvc(repo, &fakeComments{}, &fakeAudit{})
			if err := tc.first(svc, ctx, "human:bob", j); err != nil {
				t.Fatal(err)
			}
			if err := tc.next(svc, ctx, "human:bob", j); !errors.Is(err, shared.ErrConflict) {
				t.Fatalf("cross-mode replay must be rejected, got %v", err)
			}
			if len(repo.upserted) != 1 {
				t.Fatalf("cross-mode replay must not persist a second kind, got %d rows", len(repo.upserted))
			}
		})
	}
}

func TestVerifiedProjectionAttribution(t *testing.T) {
	ctx := context.Background()

	t.Run("sast inherits subject binding", func(t *testing.T) {
		repo := &fakeRepo{}
		svc := newSvc(repo, &fakeComments{}, &fakeAudit{})
		a := &projectionAttributor{asset: "asset-1", inherited: "asset-1"}
		svc.SetAttributor(a)
		j := confirmedSAST()
		j.SubjectKind, j.SubjectID = judgment.SubjectFinding, "existing-finding"
		j.Claim = judgment.SASTClaim{CWE: "CWE-89", Location: "app/dao.Find", Rule: "taint-sqli", AssetID: "ignored"}
		if err := svc.RecordConfirmedSAST(ctx, "human:bob", j); err != nil {
			t.Fatal(err)
		}
		if len(a.recorded) != 1 {
			t.Fatalf("want one binding, got %d", len(a.recorded))
		}
	})

	for _, tc := range []struct {
		name  string
		asset shared.ID
		err   error
	}{
		{"explicit standalone threat", "asset-1", nil},
		{"missing standalone threat", "", shared.ErrValidation},
		{"invalid standalone threat", "other", shared.ErrNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepo{}
			svc := newSvc(repo, &fakeComments{}, &fakeAudit{})
			a := &projectionAttributor{asset: "asset-1"}
			svc.SetAttributor(a)
			j := confirmedThreat()
			j.Claim = judgment.ThreatClaim{Category: judgment.InfoDisclosure, Asset: "legacy-pii", AssetID: tc.asset}
			err := svc.RecordConfirmedThreat(ctx, "human:bob", j)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("want %v, got %v", tc.err, err)
				}
				if len(repo.upserted) != 0 {
					t.Fatal("failed attribution must not persist")
				}
				return
			}
			if err != nil || len(a.recorded) != 1 {
				t.Fatalf("want explicit binding, err=%v recorded=%d", err, len(a.recorded))
			}
		})
	}
}
