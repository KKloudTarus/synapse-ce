package findinglineage_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	lineageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findinglineage"
)

func TestBuildNativeEvidenceRecordIaCScannerFamilies(t *testing.T) {
	for _, test := range []struct{ name, rule, path, configKind string }{
		{"terraform", "terraform-public-instance", "infra/main.tf", "terraform"},
		{"cloudformation", "cloudformation-rds-public", "infra/template.yaml", "cloudformation"},
		{"kubernetes", "kubernetes-host-network", "deploy/pod.yaml", "kubernetes"},
		{"helm", "kubernetes-host-network", "charts/service/Chart.yaml", "kubernetes"},
		{"dockerfile", "dockerfile-run-as-root", "Dockerfile", "dockerfile"},
		{"compose", "compose-privileged", "compose.yaml", "compose"},
		{"github_actions", "gha-permissions-write-all", ".github/workflows/ci.yaml", "github_actions"},
		{"arm", "arm-storage-https-only-off", "azure/template.json", "arm"},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 9, 8, 5, 0, 0, 0, time.UTC)
			item := finding.Finding{
				ID: "source-" + shared.ID(test.name), Kind: finding.KindMisconfig,
				RuleKey: test.rule, DedupKey: "misconfig:" + test.rule + ":" + test.path + ":42",
				Title: "private-source-title", Description: "private-source-description-and-rendered-value",
				Status: finding.StatusRemediated, Assignee: "private-workflow-assignee",
				Severity: shared.SeverityHigh, RiskScore: 7.5, Reachability: "unknown",
				SourceLocation: &finding.SourceLocation{File: test.path, StartLine: 42, EndLine: 44},
				Audit:          shared.Audit{CreatedAt: now},
			}
			record, err := lineageuc.BuildNativeEvidenceRecord(item, "repo:example", nil)
			if err != nil {
				t.Fatalf("scanner-supported %s finding aborted native evidence: %v", test.name, err)
			}
			if !record.InputTrusted || !record.OwnershipValidated || !record.RedactionComplete || record.ProducerKind != "iac" || record.FindingKind != "misconfig" {
				t.Fatalf("invalid retained namespace or trust flags: %+v", record)
			}
			if !record.ProvisionalIdentity || record.ReviewReason != domain.ReasonInsufficientAnchor {
				t.Fatalf("finding without semantic/resource anchors was treated as definitive: %+v", record)
			}
			fingerprint, err := domain.CanonicalizeFingerprintV1(record.FingerprintInput)
			if err != nil {
				t.Fatalf("native observation has no valid canonical identity: %v", err)
			}
			var fields map[string]any
			if err := json.Unmarshal(fingerprint.IdentityFields, &fields); err != nil {
				t.Fatal(err)
			}
			if fields["config_kind"] != test.configKind || fields["repo_path"] != test.path || fields["rule_key"] != test.rule {
				t.Fatalf("wrong canonical scanner family: %s", fingerprint.IdentityFields)
			}
			for _, key := range []string{"resource_anchor", "semantic_config_anchor", "legacy_dedup_key", "raw_offsets", "start_line", "end_line"} {
				if _, exists := fields[key]; exists {
					t.Fatalf("invented or observation-only identity field %q: %s", key, fingerprint.IdentityFields)
				}
			}
			if record.Observation.Location != test.path+":42" || record.Observation.SourceFindingID != item.ID.String() || record.Observation.Severity != shared.SeverityHigh || record.Observation.RiskScoreMilli == nil || *record.Observation.RiskScoreMilli != 7500 {
				t.Fatalf("safe observed attributes were lost: %+v", record.Observation)
			}
			payload, err := json.Marshal(lineageuc.NativeEvidence{Version: lineageuc.NativeEvidenceVersion, Records: []lineageuc.CorrelateInput{record}})
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{item.Title, item.Description, item.Assignee, item.DedupKey, string(item.Status)} {
				if strings.Contains(string(payload), forbidden) {
					t.Fatalf("raw finding or mutable workflow field leaked into evidence: %q", forbidden)
				}
			}

			// A source-line move changes observed location, never the coarse identity.
			moved := item
			moved.DedupKey = "misconfig:" + test.rule + ":" + test.path + ":900"
			moved.SourceLocation = &finding.SourceLocation{File: test.path, StartLine: 900, EndLine: 902}
			movedRecord, err := lineageuc.BuildNativeEvidenceRecord(moved, "repo:example", nil)
			if err != nil {
				t.Fatal(err)
			}
			movedFingerprint, err := domain.CanonicalizeFingerprintV1(movedRecord.FingerprintInput)
			if err != nil || movedFingerprint.Fingerprint != fingerprint.Fingerprint || movedRecord.Observation.Location != test.path+":900" {
				t.Fatalf("line movement polluted native identity: first=%s moved=%s err=%v", fingerprint.Fingerprint, movedFingerprint.Fingerprint, err)
			}
			legacy := item
			legacy.SourceLocation = nil
			legacyRecord, err := lineageuc.BuildNativeEvidenceRecord(legacy, "repo:example", nil)
			if err != nil {
				t.Fatal(err)
			}
			legacyFingerprint, err := domain.CanonicalizeFingerprintV1(legacyRecord.FingerprintInput)
			if err != nil || legacyFingerprint.Fingerprint != fingerprint.Fingerprint || legacyRecord.Observation.Location != record.Observation.Location {
				t.Fatalf("legacy source range changed retained identity: first=%s legacy=%s err=%v", fingerprint.Fingerprint, legacyFingerprint.Fingerprint, err)
			}

			repository := memory.NewFindingLineageRepository()
			service, err := lineageuc.NewService(repository, memory.NewTenantTransactionRunner(), noOpBackfillAudit{}, fixedBackfillClock{now}, &backfillIDs{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			record.TenantID, record.CycleID, record.SnapshotID, record.Actor = "tenant", "cycle", "snapshot", "scanner"
			// The projector binds scanner provenance only after selecting a sealed run.
			record.Observation.ScannerProvenance = domain.ScannerProvenance{ToolName: "iac", ScanRunID: "run", LaneKey: "iac"}
			result, err := service.Correlate(context.Background(), record)
			if err != nil || result.Outcome != lineageuc.OutcomeReview || result.Observation == nil || result.Identity == nil || result.Candidate == nil || result.Skip != nil {
				t.Fatalf("native finding was not retained for explicit review: result=%+v err=%v", result, err)
			}
			if result.Candidate.Reason != domain.ReasonInsufficientAnchor {
				t.Fatalf("wrong review reason: %+v", result.Candidate)
			}
		})
	}
}

func TestBuildNativeEvidenceRecordIaCUnknownOrUnsafeInputStillFails(t *testing.T) {
	for _, test := range []struct{ name, rule, path string }{
		{"unknown_family", "unknown-platform-rule", "config.yaml"},
		{"traversal", "dockerfile-run-as-root", "../Dockerfile"},
		{"absolute_path", "compose-privileged", "/private/compose.yaml"},
		{"credential_locator", "gha-unpinned-action", "https://user:private-test-marker@example.test/ci.yaml"},
		{"sensitive_rule", "arm-password=private-test-marker", "template.json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := finding.Finding{
				ID: "source", Kind: finding.KindMisconfig, RuleKey: test.rule,
				DedupKey:       fmt.Sprintf("misconfig:%s:%s:1", test.rule, test.path),
				SourceLocation: &finding.SourceLocation{File: test.path, StartLine: 1, EndLine: 1},
			}
			_, err := lineageuc.BuildNativeEvidenceRecord(item, "repo:example", nil)
			if !errors.Is(err, shared.ErrValidation) && !errors.Is(err, domain.ErrSensitiveInput) {
				t.Fatalf("unsafe/unknown input did not fail validation: %v", err)
			}
			if strings.Contains(err.Error(), "private-test-marker") {
				t.Fatalf("validation error exposed untrusted source material: %v", err)
			}
		})
	}
}
