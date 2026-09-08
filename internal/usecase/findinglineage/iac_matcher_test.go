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

func TestIaCMatcherV1GoldenTerraformAddressAndLineMovement(t *testing.T) {
	matcher, err := NewIaCMatcherV1([]IaCRuleAliasSetV1{{Primary: "terraform-public-instance", Aliases: []string{"tf-public-instance"}}})
	if err != nil {
		t.Fatal(err)
	}
	base := IaCFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", ConfigKind: IaCTerraform,
		SemanticConfigAnchorDigest: strings.Repeat("a", 64),
		TerraformAddress:           `module.network[0].module.service["blue]zone"].aws_instance.web[2]`,
		LegacySourceValidated:      true,
	}
	first := base
	first.LegacyDedupKey = "misconfig:tf-public-instance:infra/./Cafe\u0301.tf:42"
	second := base
	second.LegacyDedupKey = "misconfig:terraform-public-instance:infra/Café.tf:900"
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
		t.Fatalf("Terraform line movement changed identity: %s != %s", firstFingerprint.Fingerprint, secondFingerprint.Fingerprint)
	}
	const wantFingerprint = "601f24d6a4263f8c302c29241537b5c5a14f656f9e75d7b4687a46e5ac3773de"
	if firstFingerprint.Fingerprint != wantFingerprint {
		t.Fatalf("fingerprint=%s want=%s canonical=%s", firstFingerprint.Fingerprint, wantFingerprint, firstFingerprint.Bytes)
	}
	canonical := string(firstFingerprint.Bytes)
	if !strings.Contains(canonical, `"module_path":"module.network[0].module.service[\"blue]zone\"]"`) ||
		!strings.Contains(canonical, `"resource_address":"aws_instance.web[2]"`) {
		t.Fatalf("Terraform address was not canonicalized: %s", canonical)
	}
	if strings.Contains(canonical, "42") || strings.Contains(canonical, "900") {
		t.Fatalf("line leaked into IaC identity: %s", canonical)
	}

	differentModule := second
	differentModule.LegacyDedupKey = ""
	differentModule.RepoPath = "infra/Café.tf"
	differentModule.RuleKey = "terraform-public-instance"
	differentModule.TerraformAddress = `module.service["blue]zone"].module.network[0].aws_instance.web[2]`
	differentPlan, err := matcher.Build(differentModule)
	if err != nil {
		t.Fatal(err)
	}
	differentFingerprint, _ := domain.CanonicalizeFingerprintV1(differentPlan.FingerprintInput)
	if differentFingerprint.Fingerprint == firstFingerprint.Fingerprint {
		t.Fatal("Terraform module order collapsed")
	}

	differentIndex := second
	differentIndex.LegacyDedupKey = ""
	differentIndex.RepoPath = "infra/Café.tf"
	differentIndex.RuleKey = "terraform-public-instance"
	differentIndex.TerraformAddress = `module.network[1].module.service["blue]zone"].aws_instance.web[2]`
	differentIndexPlan, err := matcher.Build(differentIndex)
	if err != nil {
		t.Fatal(err)
	}
	differentIndexFingerprint, _ := domain.CanonicalizeFingerprintV1(differentIndexPlan.FingerprintInput)
	if differentIndexFingerprint.Fingerprint == firstFingerprint.Fingerprint {
		t.Fatal("Terraform module instance keys collapsed")
	}
}

func TestIaCMatcherV1CloudFormationKubernetesAndMissingAnchors(t *testing.T) {
	matcher, err := NewIaCMatcherV1(nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("b", 64)
	cloudFormation, err := matcher.Build(IaCFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", ConfigKind: IaCCloudFormation, RuleKey: "cloudformation-rds-public", RepoPath: "infra/template.yaml",
		SemanticConfigAnchorDigest: digest, CloudFormationStackPath: []string{"NetworkStack", "DataStack"}, CloudFormationLogicalID: "Database",
	})
	if err != nil || cloudFormation.ProvisionalIdentity {
		t.Fatalf("CloudFormation plan=%+v err=%v", cloudFormation, err)
	}
	reversed, err := matcher.Build(IaCFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", ConfigKind: IaCCloudFormation, RuleKey: "cloudformation-rds-public", RepoPath: "infra/template.yaml",
		SemanticConfigAnchorDigest: digest, CloudFormationStackPath: []string{"DataStack", "NetworkStack"}, CloudFormationLogicalID: "Database",
	})
	if err != nil {
		t.Fatal(err)
	}
	cloudFingerprint, _ := domain.CanonicalizeFingerprintV1(cloudFormation.FingerprintInput)
	reversedFingerprint, _ := domain.CanonicalizeFingerprintV1(reversed.FingerprintInput)
	if cloudFingerprint.Fingerprint == reversedFingerprint.Fingerprint {
		t.Fatal("CloudFormation nested stack order collapsed")
	}
	rootStack, err := matcher.Build(IaCFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", ConfigKind: IaCCloudFormation, RuleKey: "cloudformation-rds-public", RepoPath: "infra/template.yaml",
		SemanticConfigAnchorDigest: digest, CloudFormationLogicalID: "Database",
	})
	if err != nil || rootStack.ProvisionalIdentity {
		t.Fatalf("root CloudFormation plan=%+v err=%v", rootStack, err)
	}
	rootFingerprint, err := domain.CanonicalizeFingerprintV1(rootStack.FingerprintInput)
	if err != nil || strings.Contains(string(rootFingerprint.Bytes), "nested_stack_path") {
		t.Fatalf("root CloudFormation canonical=%s err=%v", rootFingerprint.Bytes, err)
	}

	kubernetes, err := matcher.Build(IaCFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", ConfigKind: IaCKubernetes, RuleKey: "kubernetes-privileged", RepoPath: "deploy/app.yaml",
		SemanticConfigAnchorDigest: digest, KubernetesIdentityApproved: true, KubernetesAPIVersion: "apps/v1", KubernetesKind: "Deployment", KubernetesName: "api",
	})
	if err != nil || kubernetes.ProvisionalIdentity {
		t.Fatalf("Kubernetes plan=%+v err=%v", kubernetes, err)
	}
	explicitDefault, err := matcher.Build(IaCFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", ConfigKind: IaCKubernetes, RuleKey: "kubernetes-privileged", RepoPath: "deploy/app.yaml",
		SemanticConfigAnchorDigest: digest, KubernetesIdentityApproved: true, KubernetesAPIVersion: "apps/v1", KubernetesKind: "Deployment", KubernetesNamespace: "default", KubernetesName: "api",
	})
	if err != nil {
		t.Fatal(err)
	}
	kubernetesFingerprint, _ := domain.CanonicalizeFingerprintV1(kubernetes.FingerprintInput)
	explicitFingerprint, _ := domain.CanonicalizeFingerprintV1(explicitDefault.FingerprintInput)
	if kubernetesFingerprint.Fingerprint != explicitFingerprint.Fingerprint {
		t.Fatal("implicit and explicit Kubernetes default namespace diverged")
	}

	unapproved, err := matcher.Build(IaCFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", ConfigKind: IaCKubernetes, RuleKey: "kubernetes-privileged", RepoPath: "deploy/app.yaml",
		SemanticConfigAnchorDigest: digest, KubernetesAPIVersion: "apps/v1", KubernetesKind: "Deployment", KubernetesName: "api",
	})
	if err != nil || !unapproved.ProvisionalIdentity || unapproved.ReasonCode != "kubernetes_source_identity_not_approved" {
		t.Fatalf("unapproved=%+v err=%v", unapproved, err)
	}
	missingSemantic, err := matcher.Build(IaCFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", ConfigKind: IaCTerraform, RuleKey: "terraform-public-instance", RepoPath: "main.tf", TerraformAddress: "aws_instance.web[0]",
	})
	if err != nil || !missingSemantic.ProvisionalIdentity || missingSemantic.ReasonCode != "missing_semantic_config_anchor" {
		t.Fatalf("missing semantic=%+v err=%v", missingSemantic, err)
	}
	if _, err := matcher.Build(IaCFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", ConfigKind: IaCTerraform, RuleKey: "terraform-public-instance", RepoPath: "main.tf",
		SemanticConfigAnchorDigest: digest, TerraformAddress: "aws_instance.web", RuntimeResourceID: "i-runtime-123",
	}); !errors.Is(err, shared.ErrValidation) || strings.Contains(err.Error(), "i-runtime-123") {
		t.Fatalf("runtime id error=%v", err)
	}
}

func TestIaCMatcherV1TerraformGrammarCollisionAndPersistence(t *testing.T) {
	matcher, err := NewIaCMatcherV1([]IaCRuleAliasSetV1{
		{Primary: "terraform:a", Aliases: []string{"legacy:shared"}},
		{Primary: "terraform:b", Aliases: []string{"legacy:shared"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("c", 64)
	for _, address := range []string{
		"module..aws_instance.web", "module.network", "aws_instance", "aws_instance.web[-1]", "aws_instance.web[key]", `aws_instance.web["unterminated]`,
	} {
		if _, err := matcher.Build(IaCFingerprintInputV1{
			TargetIdentityCanonical: "repo:example", ConfigKind: IaCTerraform, RuleKey: "terraform:a", RepoPath: "main.tf",
			SemanticConfigAnchorDigest: digest, TerraformAddress: address,
		}); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("address=%q err=%v", address, err)
		}
	}
	canonicalCount, err := matcher.Build(IaCFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", ConfigKind: IaCTerraform, RuleKey: "terraform:a", RepoPath: "main.tf",
		SemanticConfigAnchorDigest: digest, TerraformAddress: "aws_instance.web[00]",
	})
	if err != nil {
		t.Fatal(err)
	}
	countFingerprint, _ := domain.CanonicalizeFingerprintV1(canonicalCount.FingerprintInput)
	if !strings.Contains(string(countFingerprint.Bytes), `"resource_address":"aws_instance.web[0]"`) {
		t.Fatalf("count index was not canonicalized: %s", countFingerprint.Bytes)
	}

	conflict, err := matcher.Build(IaCFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", ConfigKind: IaCTerraform, RuleKey: "legacy:shared", RepoPath: "main.tf",
		SemanticConfigAnchorDigest: digest, TerraformAddress: "aws_instance.web[0]",
	})
	if err != nil || !conflict.Ambiguous || conflict.ReasonCode != "rule_alias_conflict" {
		t.Fatalf("conflict=%+v err=%v", conflict, err)
	}
	repository := memory.NewFindingLineageRepository()
	clock := fixedClock{now: time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)}
	observer := &collectingObserver{}
	service, err := NewService(repository, immediateTransactions{}, &collectingAudit{}, clock, &sequenceIDs{}, observer)
	if err != nil {
		t.Fatal(err)
	}
	input := conflict.Apply(correlateInput("iac-conflict", "unused"))
	input.Observation.SourceFindingID = "iac-source"
	result, err := service.Correlate(context.Background(), input)
	if err != nil || result.Outcome != OutcomeReview || result.Candidate == nil || result.Candidate.Reason != domain.ReasonMerge {
		t.Fatalf("result=%+v err=%v", result, err)
	}

	legacy, err := matcher.Build(IaCFingerprintInputV1{
		TargetIdentityCanonical: "repo:example", ConfigKind: IaCTerraform, LegacyDedupKey: "misconfig:terraform-public-instance:main.tf:42",
		LegacySourceValidated: true,
	})
	if err != nil || !legacy.ProvisionalIdentity {
		t.Fatalf("legacy=%+v err=%v", legacy, err)
	}
	legacyInput := legacy.Apply(correlateInput("iac-legacy", "unused"))
	legacyInput.Observation.SourceFindingID = "iac-legacy-source"
	legacyResult, err := service.Correlate(context.Background(), legacyInput)
	if err != nil || legacyResult.Outcome != OutcomeReview || legacyResult.Identity == nil || legacyResult.Candidate == nil {
		t.Fatalf("legacy result=%+v err=%v", legacyResult, err)
	}
	if len(observer.outcomes) != 2 {
		t.Fatalf("metrics=%+v", observer.outcomes)
	}

	for _, repoPath := range []string{"../main.tf", "/tmp/main.tf", `infra\main.tf`} {
		if _, err := matcher.Build(IaCFingerprintInputV1{
			TargetIdentityCanonical: "repo:example", ConfigKind: IaCTerraform, RuleKey: "terraform:a", RepoPath: repoPath,
			SemanticConfigAnchorDigest: digest, TerraformAddress: "aws_instance.web[0]",
		}); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("path=%q err=%v", repoPath, err)
		}
	}
}

func TestIaCMatcherV1RecognizesEveryNativeConfigFamily(t *testing.T) {
	matcher, err := NewIaCMatcherV1(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		rule string
		kind IaCConfigKind
	}{
		{"terraform-public-instance", "terraform"},
		{"cloudformation-rds-public", "cloudformation"},
		{"kubernetes-privileged", "kubernetes"},
		{"dockerfile-run-as-root", "dockerfile"},
		{"compose-privileged", "compose"},
		{"gha-pull-request-target", "github_actions"},
		{"arm-storage-public-blob", "arm"},
	} {
		t.Run(string(scenario.kind), func(t *testing.T) {
			for _, legacy := range []bool{false, true} {
				input := IaCFingerprintInputV1{TargetIdentityCanonical: "repo:example", RuleKey: scenario.rule, RepoPath: "infra/config.yaml"}
				if legacy {
					input.RuleKey, input.RepoPath = "", ""
					input.LegacyDedupKey = "misconfig:" + scenario.rule + ":infra/config.yaml:42"
					input.LegacySourceValidated = true
				}
				plan, err := matcher.Build(input)
				if err != nil {
					t.Fatalf("legacy=%v: %v", legacy, err)
				}
				fingerprint, err := domain.CanonicalizeFingerprintV1(plan.FingerprintInput)
				if err != nil || !strings.Contains(string(fingerprint.Bytes), `"config_kind":"`+string(scenario.kind)+`"`) {
					t.Fatalf("canonical=%s err=%v", fingerprint.Bytes, err)
				}
				if !plan.ProvisionalIdentity || !plan.Ambiguous || plan.ReviewReason != domain.ReasonInsufficientAnchor || plan.SkipInput {
					t.Fatalf("source-only input became trusted or was dropped: %+v", plan)
				}
			}
		})
	}
}

func TestIaCMatcherV1UnadaptedConfigFamiliesStayProvisional(t *testing.T) {
	matcher, err := NewIaCMatcherV1(nil)
	if err != nil {
		t.Fatal(err)
	}
	fingerprints := map[string]IaCConfigKind{}
	for _, kind := range []IaCConfigKind{"dockerfile", "compose", "github_actions", "arm"} {
		t.Run(string(kind), func(t *testing.T) {
			for _, digest := range []string{"", strings.Repeat("a", 64)} {
				plan, err := matcher.Build(IaCFingerprintInputV1{
					TargetIdentityCanonical: "repo:example", ConfigKind: kind, RuleKey: "shared-rule", RepoPath: "infra/config.yaml",
					SemanticConfigAnchorDigest: digest,
				})
				if err != nil || !plan.ProvisionalIdentity || !plan.Ambiguous || plan.ReviewReason != domain.ReasonInsufficientAnchor || plan.ReasonCode != "resource_identity_unavailable" || plan.SkipInput {
					t.Fatalf("unadapted config promoted or dropped: %+v err=%v", plan, err)
				}
				if _, exists := plan.FingerprintInput.IdentityFields["resource_anchor"]; exists {
					t.Fatal("unadapted config invented a resource anchor")
				}
				for _, key := range []string{"resource_adapter_version", "resource_identity_grammar"} {
					if _, exists := plan.FingerprintInput.IdentityFields[key]; exists {
						t.Fatalf("unadapted config claimed %s", key)
					}
				}
				if digest == "" {
					if _, exists := plan.FingerprintInput.IdentityFields["semantic_config_anchor"]; exists {
						t.Fatal("unadapted config invented a semantic anchor")
					}
				}
				fingerprint, err := domain.CanonicalizeFingerprintV1(plan.FingerprintInput)
				if err != nil {
					t.Fatal(err)
				}
				if previous, exists := fingerprints[fingerprint.Fingerprint]; exists {
					t.Fatalf("same-file config kinds collapsed: %s and %s", previous, kind)
				}
				fingerprints[fingerprint.Fingerprint] = kind
				applied := plan.Apply(CorrelateInput{InputTrusted: true})
				if !applied.ProvisionalIdentity || applied.ReviewReason != domain.ReasonInsufficientAnchor || applied.ProducerKind != "iac" || applied.FindingKind != "misconfig" {
					t.Fatalf("conservative plan lost at correlation boundary: %+v", applied)
				}
			}
		})
	}
}

func TestIaCMatcherV1UnadaptedConfigValidationStillFailsClosed(t *testing.T) {
	matcher, err := NewIaCMatcherV1(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []IaCConfigKind{"dockerfile", "compose", "github_actions", "arm"} {
		for _, scenario := range []struct {
			name string
			edit func(*IaCFingerprintInputV1)
		}{
			{"parent-path", func(input *IaCFingerprintInputV1) { input.RepoPath = "../config.yaml" }},
			{"absolute-path", func(input *IaCFingerprintInputV1) { input.RepoPath = "/tmp/config.yaml" }},
			{"backslash-path", func(input *IaCFingerprintInputV1) { input.RepoPath = `infra\config.yaml` }},
			{"sensitive-path", func(input *IaCFingerprintInputV1) { input.RepoPath = "token=never-retain-me/config.yaml" }},
			{"sensitive-rule", func(input *IaCFingerprintInputV1) { input.RuleKey = "token=never-retain-me" }},
			{"sensitive-target", func(input *IaCFingerprintInputV1) { input.TargetIdentityCanonical = "token=never-retain-me" }},
			{"invalid-digest", func(input *IaCFingerprintInputV1) { input.SemanticConfigAnchorDigest = "token=never-retain-me" }},
			{"raw-runtime", func(input *IaCFingerprintInputV1) { input.RuntimeResourceID = "never-retain-me" }},
			{"raw-rendered", func(input *IaCFingerprintInputV1) { input.RenderedValue = "never-retain-me" }},
			{"raw-offsets", func(input *IaCFingerprintInputV1) { input.RawOffsets = map[string]int{"line": 42} }},
		} {
			t.Run(string(kind)+"/"+scenario.name, func(t *testing.T) {
				input := IaCFingerprintInputV1{TargetIdentityCanonical: "repo:example", ConfigKind: kind, RuleKey: "shared-rule", RepoPath: "infra/config.yaml"}
				scenario.edit(&input)
				if _, err := matcher.Build(input); (!errors.Is(err, shared.ErrValidation) && !errors.Is(err, domain.ErrSensitiveInput)) || strings.Contains(err.Error(), "never-retain-me") {
					t.Fatalf("unsafe input accepted or leaked: %v", err)
				}
			})
		}
	}
	for _, input := range []IaCFingerprintInputV1{
		{TargetIdentityCanonical: "repo:example", RuleKey: "unknown-rule", RepoPath: "config.yaml"},
		{TargetIdentityCanonical: "repo:example", ConfigKind: "unknown", RuleKey: "terraform-public-instance", RepoPath: "config.yaml"},
		{TargetIdentityCanonical: "repo:example", ConfigKind: "unknown", RuleKey: "dockerfile-run-as-root", RepoPath: "config.yaml"},
	} {
		if _, err := matcher.Build(input); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("unsupported kind accepted: kind=%q rule=%q err=%v", input.ConfigKind, input.RuleKey, err)
		}
	}
}

func TestIaCMatcherV1UnadaptedConfigAliasConflictDoesNotPromoteIdentity(t *testing.T) {
	matcher, err := NewIaCMatcherV1([]IaCRuleAliasSetV1{
		{Primary: "config:a", Aliases: []string{"config:shared"}},
		{Primary: "config:b", Aliases: []string{"config:shared"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []IaCConfigKind{IaCDockerfile, IaCCompose, IaCGitHubActions, IaCARM} {
		plan, err := matcher.Build(IaCFingerprintInputV1{
			TargetIdentityCanonical: "repo:example", ConfigKind: kind, RuleKey: "config:shared", RepoPath: "infra/config.yaml",
			SemanticConfigAnchorDigest: strings.Repeat("a", 64),
		})
		if err != nil || !plan.ProvisionalIdentity || !plan.Ambiguous || plan.ReviewReason != domain.ReasonMerge || plan.ReasonCode != "rule_alias_conflict" {
			t.Fatalf("alias conflict lost conservative identity: kind=%s plan=%+v err=%v", kind, plan, err)
		}
	}
}
