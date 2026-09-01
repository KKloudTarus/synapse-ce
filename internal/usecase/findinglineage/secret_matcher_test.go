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

func TestSecretMatcherV1RedactsBeforeErrorAndRejectsRawMaterial(t *testing.T) {
	rawSecret := "AKIA" + "Z2K7QMN4TJ5VWXY9"
	sanitized, err := RedactSecretProducerInputV1(SecretProducerInputV1{
		TargetIdentityCanonical: "repo:example", DetectorKey: "aws-access-key-id", SecretClass: "aws_access_key",
		RepoPath: "config/app.env", Anchor: SecretAnchorV1{Kind: SecretAnchorEnvName, SchemaVersion: 1, ContainerName: "AWS_ACCESS_KEY_ID", ContainerApproved: true},
		RawSecret: rawSecret, Evidence: "assignment=" + rawSecret,
	})
	if !errors.Is(err, ErrSecretMaterialRejected) {
		t.Fatalf("raw secret error=%v", err)
	}
	if strings.Contains(err.Error(), rawSecret) || strings.Contains(err.Error(), "assignment=") {
		t.Fatalf("raw material leaked into error: %v", err)
	}
	if !sanitized.RedactionComplete || sanitized.DetectorKey != "aws-access-key-id" || sanitized.Anchor.ContainerName != "AWS_ACCESS_KEY_ID" {
		t.Fatalf("sanitized=%+v", sanitized)
	}

	unapproved, err := RedactSecretProducerInputV1(SecretProducerInputV1{
		TargetIdentityCanonical: "repo:example", DetectorKey: "generic-secret", SecretClass: "credential",
		RepoPath: "config/app.env", Anchor: SecretAnchorV1{Kind: SecretAnchorConfigKey, SchemaVersion: 1, ContainerName: "password"},
	})
	if err != nil || unapproved.Anchor.Kind != SecretAnchorConfigKey || unapproved.Anchor.ContainerName != "" {
		t.Fatalf("unapproved sanitized=%+v err=%v", unapproved, err)
	}
	matcher, err := NewSecretMatcherV1(nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := matcher.Build(unapproved)
	if err == nil || plan.ProvisionalIdentity {
		t.Fatalf("direct unapproved container must fail closed plan=%+v err=%v", plan, err)
	}
}

func TestSecretMatcherV1GoldenAliasLineMovementAndClassSeparation(t *testing.T) {
	matcher, err := NewSecretMatcherV1([]SecretDetectorAliasSetV1{{Primary: "aws-access-key-id", Aliases: []string{"aws-key"}}})
	if err != nil {
		t.Fatal(err)
	}
	build := func(legacy, class string) SecretMatchPlanV1 {
		input, redactErr := RedactSecretProducerInputV1(SecretProducerInputV1{
			TargetIdentityCanonical: "repo:example", SecretClass: class, LegacyDedupKey: legacy, LegacySourceValidated: true,
			Anchor: SecretAnchorV1{Kind: SecretAnchorEnvName, SchemaVersion: 1, ContainerName: "AWS_ACCESS_KEY_ID", ContainerApproved: true},
		})
		if redactErr != nil {
			t.Fatal(redactErr)
		}
		plan, buildErr := matcher.Build(input)
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		return plan
	}
	first := build("secret:aws-key:config/./Cafe\u0301.env:4", "aws_access_key")
	second := build("secret:aws-access-key-id:config/Café.env:900", "aws_access_key")
	firstFingerprint, err := domain.CanonicalizeFingerprintV1(first.FingerprintInput)
	if err != nil {
		t.Fatal(err)
	}
	secondFingerprint, err := domain.CanonicalizeFingerprintV1(second.FingerprintInput)
	if err != nil {
		t.Fatal(err)
	}
	if firstFingerprint.Fingerprint != secondFingerprint.Fingerprint {
		t.Fatalf("secret line movement changed identity: %s != %s", firstFingerprint.Fingerprint, secondFingerprint.Fingerprint)
	}
	const wantFingerprint = "345422cc846a454e8eb024f58cadc0dc0d32d0f728916cf5370eb30accf2ec6e"
	if firstFingerprint.Fingerprint != wantFingerprint {
		t.Fatalf("fingerprint=%s want=%s canonical=%s", firstFingerprint.Fingerprint, wantFingerprint, firstFingerprint.Bytes)
	}
	canonical := string(firstFingerprint.Bytes)
	if strings.Contains(canonical, "900") || strings.Contains(canonical, `"line"`) || strings.Contains(canonical, "AKIA") {
		t.Fatalf("observation or secret material leaked: %s", canonical)
	}

	differentClass := build("secret:aws-access-key-id:config/Café.env:900", "cloud_api_token")
	differentFingerprint, _ := domain.CanonicalizeFingerprintV1(differentClass.FingerprintInput)
	if differentFingerprint.Fingerprint == firstFingerprint.Fingerprint {
		t.Fatal("different secret classes collapsed")
	}
	duplicate := build("secret:aws-access-key-id:config/Café.env:1", "aws_access_key")
	duplicateFingerprint, _ := domain.CanonicalizeFingerprintV1(duplicate.FingerprintInput)
	if duplicateFingerprint.Fingerprint != firstFingerprint.Fingerprint {
		t.Fatal("duplicate class and container should retain identity")
	}
}

func TestSecretMatcherV1AnchorProfilesProvisionalSkipAndCollision(t *testing.T) {
	matcher, err := NewSecretMatcherV1([]SecretDetectorAliasSetV1{
		{Primary: "detector:a", Aliases: []string{"legacy:shared"}},
		{Primary: "detector:b", Aliases: []string{"legacy:shared"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	anchors := []SecretAnchorV1{
		{Kind: SecretAnchorSymbol, SchemaVersion: 1, LanguageID: "go", QualifiedSymbol: "example.Config.Load"},
		{Kind: SecretAnchorConfigKey, SchemaVersion: 1, ContainerName: "database.password", ContainerApproved: true},
		{Kind: SecretAnchorEnvName, SchemaVersion: 1, ContainerName: "DATABASE_PASSWORD", ContainerApproved: true},
		{Kind: SecretAnchorStructuredSlot, SchemaVersion: 1, ContainerName: "spec.template.secretKeyRef", ContainerApproved: true},
	}
	for _, anchor := range anchors {
		plan, buildErr := matcher.Build(SecretFingerprintInputV1{
			TargetIdentityCanonical: "repo:example", DetectorKey: "detector:a", SecretClass: "credential", RepoPath: "config/app.yaml",
			Anchor: anchor, RedactionComplete: true,
		})
		if buildErr != nil || plan.ProvisionalIdentity {
			t.Fatalf("anchor=%s plan=%+v err=%v", anchor.Kind, plan, buildErr)
		}
	}

	legacy, err := matcher.Build(SecretFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", SecretClass: "credential", LegacyDedupKey: "secret:detector:a:config/app.yaml:42",
		LegacySourceValidated: true, RedactionComplete: true,
	})
	if err != nil || !legacy.ProvisionalIdentity || legacy.ReasonCode != "missing_container_anchor" {
		t.Fatalf("legacy=%+v err=%v", legacy, err)
	}
	conflict, err := matcher.Build(SecretFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", DetectorKey: "legacy:shared", SecretClass: "credential", RepoPath: "config/app.yaml",
		Anchor: anchors[1], RedactionComplete: true,
	})
	if err != nil || !conflict.Ambiguous || conflict.ReasonCode != "detector_alias_conflict" {
		t.Fatalf("conflict=%+v err=%v", conflict, err)
	}

	repository := memory.NewFindingLineageRepository()
	clock := fixedClock{now: time.Date(2026, 9, 1, 14, 0, 0, 0, time.UTC)}
	observer := &collectingObserver{}
	service, err := NewService(repository, immediateTransactions{}, &collectingAudit{}, clock, &sequenceIDs{}, observer)
	if err != nil {
		t.Fatal(err)
	}
	conflictInput := conflict.Apply(correlateInput("secret-conflict", "unused"))
	conflictInput.Observation.SourceFindingID = "secret-source"
	conflictResult, err := service.Correlate(context.Background(), conflictInput)
	if err != nil || conflictResult.Outcome != OutcomeReview || conflictResult.Candidate == nil || conflictResult.Candidate.Reason != domain.ReasonMerge {
		t.Fatalf("conflict result=%+v err=%v", conflictResult, err)
	}

	redactionPlan, err := matcher.Build(SecretFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", DetectorKey: "detector:a", SecretClass: "credential", RepoPath: "config/app.yaml", Anchor: anchors[1],
	})
	if err != nil {
		t.Fatal(err)
	}
	redactionResult, err := service.Correlate(context.Background(), redactionPlan.Apply(correlateInput("secret-redaction", "unused")))
	if err != nil || redactionResult.Outcome != OutcomeSkipped || redactionResult.Skip == nil || redactionResult.Skip.Reason != domain.SkipRedactionRequired {
		t.Fatalf("redaction result=%+v err=%v", redactionResult, err)
	}
	if len(observer.outcomes) != 2 {
		t.Fatalf("metrics=%+v", observer.outcomes)
	}

	for _, repoPath := range []string{"../secret.env", "/tmp/secret.env", `config\secret.env`} {
		if _, err := matcher.Build(SecretFingerprintInputV1{
			TargetIdentityCanonical: "repo:example", DetectorKey: "detector:a", SecretClass: "credential", RepoPath: repoPath,
			Anchor: anchors[1], RedactionComplete: true,
		}); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("path=%q err=%v", repoPath, err)
		}
	}
}
