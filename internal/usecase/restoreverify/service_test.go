package restoreverify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	auditdom "github.com/KKloudTarus/synapse-ce/internal/domain/audit"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type evidenceReaderStub struct {
	chains []ports.RestoreEvidenceChain
	err    error
	calls  int
}

func (s *evidenceReaderStub) ListEvidenceChains(context.Context) ([]ports.RestoreEvidenceChain, error) {
	s.calls++
	return s.chains, s.err
}

type blobReaderStub struct {
	objects map[string]ports.ObjectMetadata
	errs    map[string]error
	calls   []string
}

func (s *blobReaderStub) Stat(_ context.Context, ref string) (ports.ObjectMetadata, error) {
	s.calls = append(s.calls, ref)
	if err := s.errs[ref]; err != nil {
		return ports.ObjectMetadata{}, err
	}
	return s.objects[ref], nil
}

type migrationReaderStub struct {
	migrations []ports.MigrationMetadata
	err        error
	calls      int
}

func (s *migrationReaderStub) MigrationMetadata(context.Context) ([]ports.MigrationMetadata, error) {
	s.calls++
	return s.migrations, s.err
}

type auditReaderStub struct {
	report auditdom.Report
	err    error
	calls  int
}

func (s *auditReaderStub) VerifyGlobal(context.Context) (auditdom.Report, error) {
	s.calls++
	return s.report, s.err
}

func TestNewServiceRequiresAllReaders(t *testing.T) {
	evidence := &evidenceReaderStub{}
	blobs := &blobReaderStub{}
	migrations := &migrationReaderStub{}
	audit := &auditReaderStub{}

	for _, tt := range []struct {
		name string
		e    ports.RestoreEvidenceReader
		b    ports.RestoreBlobReader
		m    ports.RestoreMigrationReader
		a    ports.RestoreAuditReader
	}{
		{"evidence", nil, blobs, migrations, audit},
		{"blobs", evidence, nil, migrations, audit},
		{"migrations", evidence, blobs, nil, audit},
		{"audit", evidence, blobs, migrations, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewService(tt.e, tt.b, tt.m, tt.a); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("NewService() error = %v, want validation error", err)
			}
		})
	}
}

func TestVerifyDeterministicallyVerifiesChainsObjectsAuditAndMigrations(t *testing.T) {
	createdAt := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	artifact := []byte("sealed artifact")
	ref := digest(artifact)
	link := evidence.Evidence{ID: "e-1", EngagementID: "eng-b", Kind: "artifact", StorageRef: ref, Content: []byte("metadata"), CreatedAt: createdAt}.Seal()
	plain := evidence.Evidence{ID: "e-2", EngagementID: "eng-a", Kind: "note", Content: []byte("note"), CreatedAt: createdAt}.Seal()
	evidenceReader := &evidenceReaderStub{chains: []ports.RestoreEvidenceChain{
		{ID: "eng-b", Items: []evidence.Evidence{link}},
		{ID: "eng-a", Items: []evidence.Evidence{plain}},
	}}
	blobs := &blobReaderStub{objects: map[string]ports.ObjectMetadata{ref: {SHA256: ref}}}
	migrations := &migrationReaderStub{migrations: []ports.MigrationMetadata{
		{Version: 12, Applied: true},
		{Version: 4, Applied: true},
	}}
	audit := &auditReaderStub{report: auditdom.Report{Intact: true, Verified: 3, Head: "audit-head"}}
	svc, err := NewService(evidenceReader, blobs, migrations, audit)
	if err != nil {
		t.Fatal(err)
	}

	first, err := svc.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("verification must be deterministic:\n%s\n%s", firstJSON, secondJSON)
	}
	if !first.Intact || first.Audit.Head != "audit-head" || len(first.EvidenceChains) != 2 {
		t.Fatalf("unexpected result: %+v", first)
	}
	if first.EvidenceChains[0].EngagementID != "eng-a" || first.EvidenceChains[1].EngagementID != "eng-b" {
		t.Fatalf("chains not sorted: %+v", first.EvidenceChains)
	}
	object := first.EvidenceChains[1].Objects[0]
	if !object.Exists || !object.IdentityMatch || object.SHA256 != ref {
		t.Fatalf("object not verified: %+v", object)
	}
	if got := []int64{first.Migrations[0].Version, first.Migrations[1].Version}; !reflect.DeepEqual(got, []int64{4, 12}) {
		t.Fatalf("migrations not sorted: %v", got)
	}
	if len(blobs.calls) != 2 || blobs.calls[0] != ref || blobs.calls[1] != ref {
		t.Fatalf("unexpected blob reads: %v", blobs.calls)
	}
	if first.Completeness != completenessIncomplete {
		t.Fatalf("missing expected state must be reported as incomplete: %+v", first)
	}
	if evidenceReader.calls != 2 || migrations.calls != 2 || audit.calls != 2 {
		t.Fatalf("verification must only call read ports: evidence=%d migrations=%d audit=%d", evidenceReader.calls, migrations.calls, audit.calls)
	}
}

func TestVerifyReportsChainAndObjectFailuresWithoutReturningContent(t *testing.T) {
	createdAt := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	missing := digest([]byte("missing"))
	mismatched := digest([]byte("expected"))
	broken := evidence.Evidence{ID: "broken", EngagementID: "eng", Kind: "artifact", StorageRef: missing, Content: []byte("secret-content"), CreatedAt: createdAt}.Seal()
	broken.Hash = "tampered"
	second := evidence.Evidence{ID: "mismatch", EngagementID: "eng", Kind: "artifact", StorageRef: mismatched, Content: []byte("other-secret"), CreatedAt: createdAt}.Seal()

	svc, err := NewService(
		&evidenceReaderStub{chains: []ports.RestoreEvidenceChain{{ID: "eng", Items: []evidence.Evidence{broken, second}}}},
		&blobReaderStub{objects: map[string]ports.ObjectMetadata{mismatched: {SHA256: digest([]byte("different"))}}, errs: map[string]error{missing: shared.ErrNotFound}},
		&migrationReaderStub{},
		&auditReaderStub{report: auditdom.Report{Intact: true}},
	)
	if err != nil {
		t.Fatal(err)
	}

	result, err := svc.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	chain := result.EvidenceChains[0]
	if result.Intact || chain.Intact || chain.Objects[0].Exists || chain.Objects[0].IdentityMatch || chain.Objects[1].IdentityMatch {
		t.Fatalf("failures must make the report non-intact: %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || contains(string(encoded), "secret-content") || contains(string(encoded), "other-secret") {
		t.Fatalf("result exposed evidence content: %s", encoded)
	}
}

func TestVerifyReturnsTopLevelReaderErrors(t *testing.T) {
	tests := []struct {
		name string
		e    *evidenceReaderStub
		m    *migrationReaderStub
		a    *auditReaderStub
		want string
	}{
		{"evidence", &evidenceReaderStub{err: errors.New("offline")}, &migrationReaderStub{}, &auditReaderStub{}, "list evidence chains"},
		{"migrations", &evidenceReaderStub{}, &migrationReaderStub{err: errors.New("offline")}, &auditReaderStub{}, "read migration metadata"},
		{"audit", &evidenceReaderStub{}, &migrationReaderStub{}, &auditReaderStub{err: errors.New("offline")}, "verify global audit chain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := NewService(tt.e, &blobReaderStub{}, tt.m, tt.a)
			if _, err := svc.Verify(context.Background()); err == nil || !contains(err.Error(), tt.want) {
				t.Fatalf("Verify() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestVerifyFailsClosedForExpectedStateMismatchesAndUnchainedAudit(t *testing.T) {
	createdAt := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	item := evidence.Evidence{ID: "e-1", EngagementID: "eng", Kind: "note", Content: []byte("metadata"), CreatedAt: createdAt}.Seal()
	manifest := ports.RestoreExpectedState{
		AuditHead:         "audit-head",
		EvidenceChains:    []ports.RestoreExpectedEvidenceChain{{EngagementID: "eng", Head: item.Hash, Count: 1}},
		MigrationVersions: []int64{7},
	}
	for _, tt := range []struct {
		name       string
		audit      auditdom.Report
		migrations []ports.MigrationMetadata
		manifest   ports.RestoreExpectedState
	}{
		{"matching", auditdom.Report{Intact: true, Head: "audit-head"}, []ports.MigrationMetadata{{Version: 7, Applied: true}}, manifest},
		{"missing evidence", auditdom.Report{Intact: true, Head: "audit-head"}, []ports.MigrationMetadata{{Version: 7, Applied: true}}, manifest},
		{"rolled back migration", auditdom.Report{Intact: true, Head: "audit-head"}, []ports.MigrationMetadata{{Version: 7, Applied: false}}, manifest},
		{"unchained audit", auditdom.Report{Intact: true, Head: "audit-head", Unchained: 1}, []ports.MigrationMetadata{{Version: 7, Applied: true}}, manifest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			chains := []ports.RestoreEvidenceChain{{ID: "eng", Items: []evidence.Evidence{item}}}
			if tt.name == "missing evidence" {
				chains = nil
			}
			svc, err := NewService(&evidenceReaderStub{chains: chains}, &blobReaderStub{}, &migrationReaderStub{migrations: tt.migrations}, &auditReaderStub{report: tt.audit}, tt.manifest)
			if err != nil {
				t.Fatal(err)
			}
			got, err := svc.Verify(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			wantIntact := tt.name == "matching"
			if got.Intact != wantIntact {
				t.Fatalf("Intact = %v, want %v: %+v", got.Intact, wantIntact, got)
			}
			if tt.name != "unchained audit" && !wantIntact && got.Completeness != completenessMismatch {
				t.Fatalf("Completeness = %q", got.Completeness)
			}
			if tt.name == "unchained audit" && got.Audit.Intact {
				t.Fatalf("unchained audit reported intact: %+v", got.Audit)
			}
		})
	}
}

func TestVerifyRejectsInvalidIdentityAndSanitizesObjectFailures(t *testing.T) {
	createdAt := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	validRef := digest([]byte("artifact"))
	invalidRef := "SECRET-INVALID-REFERENCE"
	first := evidence.Evidence{ID: "duplicate", EngagementID: "eng", Kind: "note", StorageRef: validRef, Content: []byte("one"), CreatedAt: createdAt}.Seal()
	second := evidence.Evidence{ID: "duplicate", EngagementID: "eng", Kind: "note", StorageRef: invalidRef, Content: []byte("two"), CreatedAt: createdAt}.Seal()
	blobs := &blobReaderStub{errs: map[string]error{validRef: errors.New("raw adapter secret")}}
	svc, _ := NewService(&evidenceReaderStub{chains: []ports.RestoreEvidenceChain{{ID: "eng", Items: []evidence.Evidence{first, second}}}}, blobs, &migrationReaderStub{}, &auditReaderStub{report: auditdom.Report{Intact: true}})
	got, err := svc.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Intact || got.EvidenceChains[0].Error != "identity_mismatch" {
		t.Fatalf("identity failure was not rejected: %+v", got)
	}
	if len(blobs.calls) != 0 {
		t.Fatalf("identity failure should happen before blob I/O: %v", blobs.calls)
	}

	item := evidence.Evidence{ID: "e", EngagementID: "eng", Kind: "note", StorageRef: invalidRef, Content: []byte("safe"), CreatedAt: createdAt}.Seal()
	svc, _ = NewService(&evidenceReaderStub{chains: []ports.RestoreEvidenceChain{{ID: "eng", Items: []evidence.Evidence{item}}}}, &blobReaderStub{}, &migrationReaderStub{}, &auditReaderStub{report: auditdom.Report{Intact: true}})
	got, err = svc.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	object := got.EvidenceChains[0].Objects[0]
	encoded, _ := json.Marshal(got)
	if object.Error != "invalid_reference" || object.Reference != "" || contains(string(encoded), invalidRef) {
		t.Fatalf("invalid reference leaked or was not bounded: %s", encoded)
	}

	item = evidence.Evidence{ID: "stat-fail", EngagementID: "eng", Kind: "note", StorageRef: validRef, Content: []byte("safe"), CreatedAt: createdAt}.Seal()
	svc, _ = NewService(&evidenceReaderStub{chains: []ports.RestoreEvidenceChain{{ID: "eng", Items: []evidence.Evidence{item}}}}, &blobReaderStub{errs: map[string]error{validRef: errors.New("raw adapter secret")}}, &migrationReaderStub{}, &auditReaderStub{report: auditdom.Report{Intact: true}})
	got, err = svc.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = json.Marshal(got)
	if got.EvidenceChains[0].Objects[0].Error != "stat_failed" || contains(string(encoded), "raw adapter secret") {
		t.Fatalf("adapter failure leaked or was not bounded: %s", encoded)
	}
}

func TestVerifyRejectsMismatchedEvidenceEngagement(t *testing.T) {
	item := evidence.Evidence{ID: "e", EngagementID: "other", Kind: "note", Content: []byte("safe"), CreatedAt: time.Now().UTC()}.Seal()
	svc, _ := NewService(&evidenceReaderStub{chains: []ports.RestoreEvidenceChain{{ID: "eng", Items: []evidence.Evidence{item}}}}, &blobReaderStub{}, &migrationReaderStub{}, &auditReaderStub{report: auditdom.Report{Intact: true}})
	got, err := svc.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Intact || got.EvidenceChains[0].Error != "identity_mismatch" {
		t.Fatalf("engagement identity mismatch accepted: %+v", got)
	}
}

func TestVerifyCachesReferencesAndPropagatesCancellation(t *testing.T) {
	createdAt := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	ref := digest([]byte("artifact"))
	one := evidence.Evidence{ID: "one", EngagementID: "eng", Kind: "note", StorageRef: ref, Content: []byte("one"), CreatedAt: createdAt}.Seal()
	two := evidence.Evidence{ID: "two", EngagementID: "eng", Kind: "note", StorageRef: ref, PreviousHash: one.Hash, Content: []byte("two"), CreatedAt: createdAt}.Seal()
	blobs := &blobReaderStub{objects: map[string]ports.ObjectMetadata{ref: {SHA256: ref}}}
	svc, _ := NewService(&evidenceReaderStub{chains: []ports.RestoreEvidenceChain{{ID: "eng", Items: []evidence.Evidence{one, two}}}}, blobs, &migrationReaderStub{}, &auditReaderStub{report: auditdom.Report{Intact: true}})
	if _, err := svc.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(blobs.calls, []string{ref}) {
		t.Fatalf("Stat calls = %v, want one unique reference", blobs.calls)
	}

	blobs = &blobReaderStub{errs: map[string]error{ref: context.Canceled}}
	svc, _ = NewService(&evidenceReaderStub{chains: []ports.RestoreEvidenceChain{{ID: "eng", Items: []evidence.Evidence{one}}}}, blobs, &migrationReaderStub{}, &auditReaderStub{report: auditdom.Report{Intact: true}})
	_, err := svc.Verify(context.Background())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify() error = %v, want wrapped cancellation", err)
	}
}
