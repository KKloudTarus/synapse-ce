package findinglineage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

func TestQualityMatcherV1GoldenLegacyLineMovementAliasAndClassSeparation(t *testing.T) {
	matcher, err := NewQualityMatcherV1([]QualityRuleProfileV1{
		{Primary: "quality:cognitive-complexity", Aliases: []string{"legacy:complexity"}},
		{Primary: "quality:file-license", OneFindingPerFile: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := QualityFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", FindingClass: "quality",
		Anchor:                QualityAnchorV1{Kind: QualityAnchorSymbol, SchemaVersion: 1, LanguageID: "Go", QualifiedSymbol: "example.Handler.Serve"},
		LegacySourceValidated: true,
	}
	first := base
	first.LegacyDedupKey = "cq:quality:legacy:complexity:src/./Cafe\u0301.go:42"
	second := base
	second.LegacyDedupKey = "cq:quality:quality:cognitive-complexity:src/Café.go:900"
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
		t.Fatalf("quality line movement changed identity: %s != %s", firstFingerprint.Fingerprint, secondFingerprint.Fingerprint)
	}
	const wantFingerprint = "f6f8fc7b1c9a0dd2692fce3f835aea2b0a95e4bd4be34fd668aec5d97d380965"
	if firstFingerprint.Fingerprint != wantFingerprint {
		t.Fatalf("fingerprint=%s want=%s canonical=%s", firstFingerprint.Fingerprint, wantFingerprint, firstFingerprint.Bytes)
	}
	if strings.Contains(string(firstFingerprint.Bytes), "42") || strings.Contains(string(firstFingerprint.Bytes), "900") {
		t.Fatalf("line leaked into quality identity: %s", firstFingerprint.Bytes)
	}

	reliability := second
	reliability.FindingClass = "reliability"
	reliability.LegacyDedupKey = ""
	reliability.RepoPath = "src/Café.go"
	reliability.RuleKey = "quality:cognitive-complexity"
	reliabilityPlan, err := matcher.Build(reliability)
	if err != nil {
		t.Fatal(err)
	}
	reliabilityFingerprint, _ := domain.CanonicalizeFingerprintV1(reliabilityPlan.FingerprintInput)
	if reliabilityFingerprint.Fingerprint == firstFingerprint.Fingerprint || reliabilityPlan.FingerprintInput.ProducerKind != "reliability" {
		t.Fatal("quality and reliability identities collapsed")
	}
}

func TestQualityMatcherV1AnchorPoliciesLegacyAndUnsafePaths(t *testing.T) {
	matcher, err := NewQualityMatcherV1([]QualityRuleProfileV1{
		{Primary: "quality:file-license", OneFindingPerFile: true},
		{Primary: "quality:symbol"},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	for _, testCase := range []struct {
		name   string
		rule   string
		anchor QualityAnchorV1
	}{
		{name: "symbol", rule: "quality:symbol", anchor: QualityAnchorV1{Kind: QualityAnchorSymbol, SchemaVersion: 1, LanguageID: "go", QualifiedSymbol: "example.Run"}},
		{name: "ast", rule: "quality:symbol", anchor: QualityAnchorV1{Kind: QualityAnchorAST, SchemaVersion: 1, NodeKind: "function_declaration", AncestorNameDigest: digest}},
		{name: "file", rule: "quality:file-license", anchor: QualityAnchorV1{Kind: QualityAnchorFile, SchemaVersion: 1}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			plan, buildErr := matcher.Build(QualityFingerprintInputV1{
				TargetIdentityCanonical: "repo:example", FindingClass: "quality", RepoPath: "src/app.go", RuleKey: testCase.rule, Anchor: testCase.anchor,
			})
			if buildErr != nil || plan.ProvisionalIdentity {
				t.Fatalf("plan=%+v err=%v", plan, buildErr)
			}
		})
	}

	undeclared, err := matcher.Build(QualityFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", FindingClass: "quality", RepoPath: "src/app.go", RuleKey: "quality:symbol",
		Anchor: QualityAnchorV1{Kind: QualityAnchorFile, SchemaVersion: 1},
	})
	if err != nil || !undeclared.ProvisionalIdentity || undeclared.ReasonCode != "file_anchor_not_declared" {
		t.Fatalf("undeclared file anchor=%+v err=%v", undeclared, err)
	}
	anchorless, err := matcher.Build(QualityFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", FindingClass: "quality", LegacyDedupKey: "cq:quality:quality:symbol:src/app.go:42", LegacySourceValidated: true,
	})
	if err != nil || !anchorless.ProvisionalIdentity || anchorless.ReasonCode != "missing_semantic_anchor" {
		t.Fatalf("anchorless=%+v err=%v", anchorless, err)
	}
	malformed, err := matcher.Build(QualityFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", FindingClass: "reliability", LegacyDedupKey: "cq:reliability:broken", LegacySourceValidated: true,
	})
	if err != nil || !malformed.ProvisionalIdentity || malformed.ReasonCode != "legacy_key_malformed" {
		t.Fatalf("malformed=%+v err=%v", malformed, err)
	}
	for _, repoPath := range []string{"../outside.go", "/tmp/app.go", `src\app.go`} {
		if _, err := matcher.Build(QualityFingerprintInputV1{
			TargetIdentityCanonical: "repo:example", FindingClass: "quality", RepoPath: repoPath, RuleKey: "quality:symbol",
			Anchor: QualityAnchorV1{Kind: QualityAnchorSymbol, SchemaVersion: 1, LanguageID: "go", QualifiedSymbol: "example.Run"},
		}); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("path=%q err=%v", repoPath, err)
		}
	}
}

func TestQualityMatcherV1AliasConflictAndMemoryCandidatePersistence(t *testing.T) {
	matcher, err := NewQualityMatcherV1([]QualityRuleProfileV1{
		{Primary: "quality:a", Aliases: []string{"legacy:shared"}},
		{Primary: "quality:b", Aliases: []string{"legacy:shared"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	conflict, err := matcher.Build(QualityFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", FindingClass: "quality", RepoPath: "src/app.go", RuleKey: "legacy:shared",
		Anchor: QualityAnchorV1{Kind: QualityAnchorSymbol, SchemaVersion: 1, LanguageID: "go", QualifiedSymbol: "example.Run"},
	})
	if err != nil || !conflict.Ambiguous || conflict.ReviewReason != domain.ReasonMerge || conflict.ReasonCode != "rule_alias_conflict" {
		t.Fatalf("conflict=%+v err=%v", conflict, err)
	}

	repository := memory.NewFindingLineageRepository()
	clock := fixedClock{now: time.Date(2026, 9, 1, 13, 0, 0, 0, time.UTC)}
	observer := &collectingObserver{}
	service, err := NewService(repository, immediateTransactions{}, &collectingAudit{}, clock, &sequenceIDs{}, observer)
	if err != nil {
		t.Fatal(err)
	}
	input := conflict.Apply(correlateInput("quality-conflict", "unused"))
	input.Observation.SourceFindingID = "quality-source"
	result, err := service.Correlate(context.Background(), input)
	if err != nil || result.Outcome != OutcomeReview || result.Candidate == nil || result.Candidate.Reason != domain.ReasonMerge {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if len(observer.outcomes) != 1 || observer.outcomes[0] != "needs_review:matcher:rule_alias_conflict" {
		t.Fatalf("metrics=%+v", observer.outcomes)
	}

	provisional, err := matcher.Build(QualityFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", FindingClass: "reliability", RepoPath: "src/app.go", RuleKey: "quality:a",
	})
	if err != nil || !provisional.ProvisionalIdentity {
		t.Fatalf("provisional=%+v err=%v", provisional, err)
	}
	provisionalInput := provisional.Apply(correlateInput("quality-provisional", "unused"))
	provisionalInput.Observation.SourceFindingID = "reliability-source"
	provisionalResult, err := service.Correlate(context.Background(), provisionalInput)
	if err != nil || provisionalResult.Outcome != OutcomeReview || provisionalResult.Identity == nil || provisionalResult.Candidate == nil {
		t.Fatalf("provisional result=%+v err=%v", provisionalResult, err)
	}
	if strings.Contains(string(provisionalResult.Identity.CanonicalIdentityFields), provisionalInput.Observation.SourceFindingID) {
		t.Fatalf("raw source id leaked into provisional identity: %s", provisionalResult.Identity.CanonicalIdentityFields)
	}
}
