package findinglineage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

func TestSASTMatcherV1GoldenCanonicalProfilesAndLineMovement(t *testing.T) {
	matcher, err := NewSASTMatcherV1([]SASTRuleAliasSetV1{{Primary: "go:sql-injection", Aliases: []string{"legacy:sqli"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := matcher.Descriptor().Validate(); err != nil {
		t.Fatal(err)
	}

	base := SASTFingerprintInputV1{
		TargetIdentityCanonical: "repo:example",
		Anchor: SASTAnchorV1{
			Kind: SASTAnchorSymbol, SchemaVersion: 1, LanguageID: "Go", QualifiedSymbol: "example.Handler.Serve",
		},
		LegacySourceValidated: true, LegacyOwnershipValid: true,
	}
	first := base
	first.LegacyDedupKey = "cq:sast:legacy:sqli:src/./Cafe\u0301.go:42"
	second := base
	second.LegacyDedupKey = "cq:sast:go:sql-injection:src/Café.go:900"

	firstPlan, err := matcher.Build(first)
	if err != nil {
		t.Fatal(err)
	}
	secondPlan, err := matcher.Build(second)
	if err != nil {
		t.Fatal(err)
	}
	firstFingerprint, err := domain.CanonicalizeFingerprintV1(firstPlan.FingerprintInput)
	if err != nil {
		t.Fatal(err)
	}
	secondFingerprint, err := domain.CanonicalizeFingerprintV1(secondPlan.FingerprintInput)
	if err != nil {
		t.Fatal(err)
	}
	if firstFingerprint.Fingerprint != secondFingerprint.Fingerprint {
		t.Fatalf("line movement or approved rule alias changed identity: %s != %s", firstFingerprint.Fingerprint, secondFingerprint.Fingerprint)
	}
	const wantFingerprint = "a1a68cbafe4ec3186633549a1f4253ac8b46007cca1698fb1a6308bf6d982b54"
	if firstFingerprint.Fingerprint != wantFingerprint {
		t.Fatalf("fingerprint=%s want=%s canonical=%s", firstFingerprint.Fingerprint, wantFingerprint, firstFingerprint.Bytes)
	}
	canonical := string(firstFingerprint.Bytes)
	if strings.Contains(canonical, `"line"`) || strings.Contains(canonical, "42") || strings.Contains(canonical, "900") {
		t.Fatalf("raw line leaked into identity: %s", canonical)
	}
	if !strings.Contains(canonical, `"repo_path":"src/Café.go"`) || !strings.Contains(canonical, `"qualified_symbol":"example.Handler.Serve"`) {
		t.Fatalf("path or symbol normalization missing: %s", canonical)
	}

	caseChanged := second
	caseChanged.LegacyDedupKey = "cq:sast:go:sql-injection:src/café.go:900"
	casePlan, err := matcher.Build(caseChanged)
	if err != nil {
		t.Fatal(err)
	}
	caseFingerprint, _ := domain.CanonicalizeFingerprintV1(casePlan.FingerprintInput)
	if caseFingerprint.Fingerprint == firstFingerprint.Fingerprint {
		t.Fatal("repository path case must be preserved")
	}
}

func TestSASTMatcherV1AnchorProfilesAndUnsafeInputs(t *testing.T) {
	matcher, err := NewSASTMatcherV1(nil)
	if err != nil {
		t.Fatal(err)
	}
	digestA := strings.Repeat("a", 64)
	digestB := strings.Repeat("b", 64)
	anchors := []SASTAnchorV1{
		{Kind: SASTAnchorSymbol, SchemaVersion: 1, LanguageID: "typescript", QualifiedSymbol: "api.UserController.create"},
		{Kind: SASTAnchorAST, SchemaVersion: 1, NodeKind: "Call_Expression", AncestorNameDigest: digestA},
		{Kind: SASTAnchorDataflow, SchemaVersion: 2, SourceRuleClass: "http.request", SinkRuleClass: "sql.execute", GraphAnchorDigest: digestB},
		{Kind: SASTAnchorJudgment, SchemaVersion: 1, JudgmentID: "judgment-1", JudgmentSemanticDigest: digestA},
	}
	seen := map[string]struct{}{}
	for _, anchor := range anchors {
		plan, buildErr := matcher.Build(SASTFingerprintInputV1{
			TargetIdentityCanonical: "repo:example", RepoPath: "src/app.ts", RuleKey: "ts:rule", Anchor: anchor,
		})
		if buildErr != nil {
			t.Fatalf("anchor=%s err=%v", anchor.Kind, buildErr)
		}
		fingerprint, canonicalErr := domain.CanonicalizeFingerprintV1(plan.FingerprintInput)
		if canonicalErr != nil {
			t.Fatal(canonicalErr)
		}
		if _, exists := seen[fingerprint.Fingerprint]; exists {
			t.Fatalf("anchor profile collapsed: %s", anchor.Kind)
		}
		seen[fingerprint.Fingerprint] = struct{}{}
	}

	for _, input := range []SASTFingerprintInputV1{
		{TargetIdentityCanonical: "repo:example", RepoPath: "../outside.go", RuleKey: "go:rule", Anchor: anchors[0]},
		{TargetIdentityCanonical: "repo:example", RepoPath: "/tmp/app.go", RuleKey: "go:rule", Anchor: anchors[0]},
		{TargetIdentityCanonical: "repo:example", RepoPath: `src\app.go`, RuleKey: "go:rule", Anchor: anchors[0]},
		{TargetIdentityCanonical: "repo:example", RepoPath: "src/app.go", RuleKey: "go:rule", Anchor: SASTAnchorV1{Kind: SASTAnchorSymbol, SchemaVersion: 1, LanguageID: "go", QualifiedSymbol: "main.run", RawOffsets: map[string]int{"line": 42}}},
	} {
		if _, buildErr := matcher.Build(input); !errors.Is(buildErr, shared.ErrValidation) {
			t.Fatalf("unsafe input err=%v input=%+v", buildErr, input)
		}
	}
}

func TestSASTMatcherV1LegacyJudgmentAndRuleConflictOutcomes(t *testing.T) {
	matcher, err := NewSASTMatcherV1([]SASTRuleAliasSetV1{
		{Primary: "go:sql", Aliases: []string{"legacy:sql"}},
		{Primary: "go:command", Aliases: []string{"legacy:sql"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	current := judgment.Judgment{
		ID: "judgment-1", EngagementID: "assessment-1", Capability: judgment.CapSAST,
		SubjectKind: judgment.SubjectFinding, SubjectID: "finding-1",
		Claim: judgment.SASTClaim{CWE: "CWE-89", Location: "src/db.go:42", Rule: "go:sql", AssetID: "asset-1"},
		State: judgment.StateConfirmed, EvidenceScore: 100,
	}
	anchor, err := SASTJudgmentAnchorV1("assessment-1", current)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SASTJudgmentAnchorV1("assessment-2", current); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("ownership error=%v", err)
	}
	moved := current
	moved.Claim = judgment.SASTClaim{CWE: "CWE-89", Location: "src/db.go:900", Rule: "go:sql", AssetID: "asset-1"}
	movedAnchor, err := SASTJudgmentAnchorV1("assessment-1", moved)
	if err != nil || movedAnchor.JudgmentSemanticDigest != anchor.JudgmentSemanticDigest {
		t.Fatalf("judgment line movement changed semantic digest: %+v err=%v", movedAnchor, err)
	}

	resolved, err := matcher.Build(SASTFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", RepoPath: "src/db.go", RuleKey: "go:sql",
		LegacyDedupKey: "sast:ai:judgment-1", LegacySourceValidated: true, LegacyOwnershipValid: true, JudgmentAnchor: &anchor,
	})
	if err != nil || resolved.ProvisionalIdentity || resolved.ReasonCode != "legacy_judgment_resolved" {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	missing, err := matcher.Build(SASTFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", RepoPath: "src/db.go", RuleKey: "go:sql",
		LegacyDedupKey: "sast:ai:judgment-1", LegacySourceValidated: true, LegacyOwnershipValid: true,
	})
	if err != nil || !missing.ProvisionalIdentity || missing.ReviewReason != domain.ReasonLegacyAmbiguous || missing.ReasonCode != "legacy_judgment_missing" {
		t.Fatalf("missing=%+v err=%v", missing, err)
	}
	mismatchAnchor := anchor
	mismatchAnchor.JudgmentID = "judgment-2"
	mismatch, err := matcher.Build(SASTFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", RepoPath: "src/db.go", RuleKey: "go:sql",
		LegacyDedupKey: "sast:ai:judgment-1", LegacySourceValidated: true, LegacyOwnershipValid: true, JudgmentAnchor: &mismatchAnchor,
	})
	if err != nil || !mismatch.ProvisionalIdentity || mismatch.ReasonCode != "legacy_judgment_mismatch" {
		t.Fatalf("mismatch=%+v err=%v", mismatch, err)
	}
	conflict, err := matcher.Build(SASTFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", RepoPath: "src/db.go", RuleKey: "legacy:sql", Anchor: anchor,
	})
	if err != nil || !conflict.Ambiguous || conflict.ReviewReason != domain.ReasonMerge || conflict.ReasonCode != "rule_alias_conflict" {
		t.Fatalf("conflict=%+v err=%v", conflict, err)
	}
}

func TestSASTMatcherV1MemoryCorrelationProvisionalSkipAndRename(t *testing.T) {
	matcher, err := NewSASTMatcherV1(nil)
	if err != nil {
		t.Fatal(err)
	}
	repository := memory.NewFindingLineageRepository()
	clock := fixedClock{now: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	observer := &collectingObserver{}
	service, err := NewService(repository, immediateTransactions{}, &collectingAudit{}, clock, &sequenceIDs{}, observer)
	if err != nil {
		t.Fatal(err)
	}
	anchor := SASTAnchorV1{Kind: SASTAnchorSymbol, SchemaVersion: 1, LanguageID: "go", QualifiedSymbol: "example.Handler.Serve"}

	correlate := func(snapshot, source, location string) Result {
		plan, buildErr := matcher.Build(SASTFingerprintInputV1{
			TargetIdentityCanonical: "repo:example", RepoPath: "src/handler.go", RuleKey: "go:sqli", Anchor: anchor,
		})
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		input := plan.Apply(correlateInput(snapshot, "unused"))
		input.SnapshotID = shared.ID(snapshot)
		input.Observation.ID = shared.ID("observation-" + snapshot)
		input.Observation.SourceFindingID = source
		input.Observation.Location = location
		result, correlateErr := service.Correlate(context.Background(), input)
		if correlateErr != nil {
			t.Fatal(correlateErr)
		}
		return result
	}
	first := correlate("snapshot-1", "source-1", "src/handler.go:42")
	second := correlate("snapshot-2", "source-2", "src/handler.go:900")
	if first.Outcome != OutcomeCreated || second.Outcome != OutcomeMatched || first.Identity.ID != second.Identity.ID {
		t.Fatalf("line movement first=%+v second=%+v", first, second)
	}

	malformed, err := matcher.Build(SASTFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", LegacyDedupKey: "cq:sast:broken",
		LegacySourceValidated: true, LegacyOwnershipValid: true,
	})
	if err != nil || !malformed.ProvisionalIdentity || malformed.ReasonCode != "legacy_key_malformed" {
		t.Fatalf("malformed=%+v err=%v", malformed, err)
	}
	malformedInput := malformed.Apply(correlateInput("malformed", "unused"))
	malformedResult, err := service.Correlate(context.Background(), malformedInput)
	if err != nil || malformedResult.Outcome != OutcomeReview || malformedResult.Identity == nil || malformedResult.Candidate == nil {
		t.Fatalf("malformed result=%+v err=%v", malformedResult, err)
	}

	invalidOwnership, err := matcher.Build(SASTFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", RepoPath: "src/db.go", RuleKey: "go:sql", Anchor: anchor,
		LegacyDedupKey: "sast:ai:foreign", LegacySourceValidated: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	skipResult, err := service.Correlate(context.Background(), invalidOwnership.Apply(correlateInput("skip", "unused")))
	if err != nil || skipResult.Outcome != OutcomeSkipped || skipResult.Skip == nil || skipResult.Skip.Reason != domain.SkipInvalidOwnership {
		t.Fatalf("skip=%+v err=%v", skipResult, err)
	}

	rename, err := matcher.Build(SASTFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", RepoPath: "src/new.go", PriorRepoPath: "src/old.go", RuleKey: "go:sqli", Anchor: anchor,
	})
	if err != nil {
		t.Fatal(err)
	}
	renameResult, err := service.Correlate(context.Background(), rename.Apply(correlateInput("rename", "unused")))
	if err != nil || renameResult.Outcome != OutcomeReview || renameResult.Candidate == nil || renameResult.Reason != "unapproved_path_change" {
		t.Fatalf("rename=%+v err=%v", renameResult, err)
	}
	if len(observer.outcomes) != 5 {
		t.Fatalf("metrics outcomes=%+v", observer.outcomes)
	}
	if _, err := matcher.Build(SASTFingerprintInputV1{
		TargetIdentityCanonical: "repo:example?api_token=must-not-hash", RepoPath: "src/app.go", RuleKey: "go:rule", Anchor: anchor,
	}); !errors.Is(err, domain.ErrSensitiveInput) {
		t.Fatalf("sensitive target error=%v", err)
	}
}
