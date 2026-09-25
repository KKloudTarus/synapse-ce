package scabench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestValidateFixedTargetMatrix(t *testing.T) {
	catalog := bench.Catalog{Targets: make([]bench.Target, len(fixedTargetIDs))}
	for index, targetID := range fixedTargetIDs {
		catalog.Targets[index] = bench.Target{ID: targetID}
	}
	if err := validateFixedTargetMatrix(catalog); err != nil {
		t.Fatalf("validate fixed matrix: %v", err)
	}
	catalog.Targets = catalog.Targets[:1]
	if err := validateFixedTargetMatrix(catalog); err == nil {
		t.Fatal("catalog missing a fixed benchmark target was accepted")
	}
}

func TestValidateStagedCycleOrderRejectsFalseComparisonAndBrokenReceipt(t *testing.T) {
	catalog := bench.Catalog{Targets: make([]bench.Target, 0, len(fixedTargetIDs))}
	oracle := bench.Oracle{Cases: make([]bench.OracleCase, 0, len(fixedTargetIDs))}
	for _, targetID := range fixedTargetIDs {
		catalog.Targets = append(catalog.Targets, bench.Target{ID: targetID})
		coverage := make(map[bench.Engine]bench.Coverage)
		for _, engine := range bench.Engines() {
			coverage[engine] = bench.CoverageCovered
		}
		oracle.Cases = append(oracle.Cases, bench.OracleCase{TargetID: targetID, ExpectedCoverage: coverage})
	}
	run := RunResult{Observations: make([][]bench.Observation, fixedRepetitions), RawBundles: make([][]BundleIdentity, fixedRepetitions)}
	for _, target := range catalog.Targets {
		for _, engine := range bench.Engines() {
			observation := bench.Observation{TargetID: target.ID, Engine: engine, State: bench.ObservationComplete,
				RawOutputDigest: sha256Digest([]byte("raw")), EnvironmentDigest: sha256Digest([]byte("environment")), SBOMDigest: sha256Digest([]byte("sbom"))}
			files := []BundleFileIdentity{
				{Name: "evidence.json", Digest: sha256Digest([]byte("evidence")), Size: 1},
				{Name: "observation.json", Digest: sha256Digest([]byte(target.ID + string(engine))), Size: 1},
			}
			manifest, err := bench.CanonicalJSON(files)
			if err != nil {
				t.Fatal(err)
			}
			rootMaterial := []byte(files[0].Name + "\x00" + files[0].Digest + "\x00" + files[1].Name + "\x00" + files[1].Digest + "\x00")
			identity := BundleIdentity{TargetID: target.ID, Engine: engine, ManifestDigest: sha256Digest(manifest), RootDigest: sha256Digest(rootMaterial), Files: files,
				NormalizedObservationDigest: files[1].Digest, RawOutputDigest: observation.RawOutputDigest, ProcessEvidenceDigest: files[0].Digest,
				EnvironmentDigest: observation.EnvironmentDigest, SBOMDigest: observation.SBOMDigest}
			for repetition := range fixedRepetitions {
				run.Observations[repetition] = append(run.Observations[repetition], observation)
				run.RawBundles[repetition] = append(run.RawBundles[repetition], identity)
			}
			claimObservation := observation
			claimObservation.RawOutputDigest = ""
			claim := BundleClaim{Observation: claimObservation, ExpectedState: bench.ObservationComplete}
			run.Comparisons = append(run.Comparisons, SemanticBundleComparison{SchemaVersion: semanticBundleComparisonSchema, TargetID: target.ID, Engine: engine,
				ExpectedState: bench.ObservationComplete, Left: identity, Right: identity, LeftClaim: claim, RightClaim: claim, SemanticEqual: true})
		}
	}
	if err := ValidateStagedCycleOrder(run, catalog, oracle); err != nil {
		t.Fatalf("valid cycle rejected: %v", err)
	}
	run.Comparisons[0].SemanticEqual = false
	if err := ValidateStagedCycleOrder(run, catalog, oracle); err == nil {
		t.Fatal("false semantic comparison was accepted")
	}
	run.Comparisons[0].SemanticEqual = true
	run.RawBundles[0][0].RootDigest = sha256Digest([]byte("forged"))
	if err := ValidateStagedCycleOrder(run, catalog, oracle); err == nil {
		t.Fatal("broken raw bundle receipt was accepted")
	}
}

func TestThreeTargetPublicationAcceptsExactArtifactSet(t *testing.T) {
	catalog, files := completePublicationArtifacts()
	if got, want := len(files), expectedPublicationFileCount(); got != want {
		t.Fatalf("publication artifact count = %d, want %d", got, want)
	}
	if err := validateStagedArtifactSet(catalog, files); err != nil {
		t.Fatalf("complete fixed publication artifact set rejected: %v", err)
	}

	state := testPublicationState(t)
	state.runtimeCleanup = func(context.Context) error { return nil }
	state.stageVerifier = func(ctx context.Context, stage string, identities []benchcycle.FileIdentity) error {
		staged, err := publicationStageFiles(ctx, stage, identities)
		if err != nil {
			return err
		}
		return validateStagedArtifactSet(catalog, staged)
	}
	publication, err := state.beginPublication()
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range files {
		if _, err := publication.WriteBytes(context.Background(), path, body); err != nil {
			t.Fatalf("stage publication artifact %q: %v", path, err)
		}
	}
	if err := publication.Commit(context.Background()); err != nil {
		t.Fatalf("publish complete three-target artifact set: %v", err)
	}
}

func TestThreeTargetPublicationRejectsMissingAndUnexpectedArtifacts(t *testing.T) {
	catalog, complete := completePublicationArtifacts()
	for _, test := range []struct {
		name   string
		mutate func(map[string][]byte)
	}{
		{
			name: "missing fixed artifact",
			mutate: func(files map[string][]byte) {
				delete(files, "result.json")
			},
		},
		{
			name: "unexpected artifact",
			mutate: func(files map[string][]byte) {
				files["extra.json"] = []byte("extra")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			files := make(map[string][]byte, len(complete))
			for path, body := range complete {
				files[path] = body
			}
			test.mutate(files)
			if err := validateStagedArtifactSet(catalog, files); err == nil {
				t.Fatal("incomplete or unexpected publication artifact set was accepted")
			}
		})
	}
}

func TestRequireTrustedCycleResultRejectsMissingOrFailedAbsoluteGate(t *testing.T) {
	for _, result := range []bench.Result{
		{},
		{Gate: &bench.Gate{Passed: false}},
	} {
		if err := requireTrustedCycleResult(result); err == nil {
			t.Fatal("result without a passed absolute gate was accepted")
		}
	}
}

func TestRequireTrustedCycleResultRejectsMeasuredComparatorRecallBreach(t *testing.T) {
	result := measuredCycleResult(0.5)
	if err := requireTrustedCycleResult(result); err == nil {
		t.Fatal("result with a comparator recall above owned recall was accepted")
	}
}

func TestCanonicalCapabilityComponentsUsesBenchmarkIdentityOrder(t *testing.T) {
	version := "4.4-150400.25.22"
	components, err := canonicalCapabilityComponents(bench.CapabilityKindOSVScannerSUSERPM, []bench.Component{
		{PURL: "pkg:rpm/sles/bash-sh@" + version, Version: version},
		{PURL: "pkg:rpm/sles/bash@" + version, Version: version},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 2 || components[0].PURL != "pkg:rpm/sles/bash@"+version || components[1].PURL != "pkg:rpm/sles/bash-sh@"+version {
		t.Fatalf("capability component order = %+v", components)
	}
}

func TestCanonicalCapabilityComponentsFiltersNonApplicableEcosystems(t *testing.T) {
	version := "1.2.3-4.el9"
	components, err := canonicalCapabilityComponents(bench.CapabilityKindOSVScannerRedHatEnterpriseLinuxRPM, []bench.Component{
		{PURL: "pkg:pypi/example@1.2.3", Version: "1.2.3"},
		{PURL: "pkg:rpm/redhat/example@" + version, Version: version},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 1 || components[0].PURL != "pkg:rpm/redhat/example@"+version {
		t.Fatalf("capability components = %+v", components)
	}
}

func TestValidateReviewEvidence(t *testing.T) {
	const implementationCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	review, disposition := validReviewEvidence(implementationCommit)
	reviewBody, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	dispositionBody, err := json.Marshal(disposition)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateReviewEvidence(reviewBody, dispositionBody, implementationCommit); err != nil {
		t.Fatalf("valid review evidence rejected: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*reviewCapture, *dispositionCapture)
	}{
		{name: "review schema missing", mutate: func(review *reviewCapture, _ *dispositionCapture) { review.SchemaVersion = "" }},
		{name: "review schema wrong", mutate: func(review *reviewCapture, _ *dispositionCapture) { review.SchemaVersion = "review-v2" }},
		{name: "disposition schema missing", mutate: func(_ *reviewCapture, disposition *dispositionCapture) { disposition.SchemaVersion = "" }},
		{name: "disposition schema wrong", mutate: func(_ *reviewCapture, disposition *dispositionCapture) { disposition.SchemaVersion = "disposition-v2" }},
		{name: "non HTTPS review URL", mutate: func(review *reviewCapture, _ *dispositionCapture) {
			review.URL = "http://github.com/example-owner/example-repository/pull/321#pullrequestreview-1234"
		}},
		{name: "credentialed review URL", mutate: func(review *reviewCapture, _ *dispositionCapture) {
			review.URL = "https://reviewer:secret@github.com/example-owner/example-repository/pull/321#pullrequestreview-1234"
		}},
		{name: "non GitHub review URL", mutate: func(review *reviewCapture, _ *dispositionCapture) {
			review.URL = "https://example.invalid/example-owner/example-repository/pull/321#pullrequestreview-1234"
		}},
		{name: "review fragment differs from ID", mutate: func(review *reviewCapture, _ *dispositionCapture) {
			review.URL = "https://github.com/example-owner/example-repository/pull/321#pullrequestreview-9999"
		}},
		{name: "disposition fragment differs from ID", mutate: func(_ *reviewCapture, disposition *dispositionCapture) {
			disposition.URL = "https://github.com/example-owner/example-repository/pull/321#issuecomment-9999"
		}},
		{name: "reviewed commit differs", mutate: func(review *reviewCapture, disposition *dispositionCapture) {
			review.CommitID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			disposition.ReviewedCommit = review.CommitID
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			review, disposition := validReviewEvidence(implementationCommit)
			test.mutate(&review, &disposition)
			reviewBody, err := json.Marshal(review)
			if err != nil {
				t.Fatal(err)
			}
			dispositionBody, err := json.Marshal(disposition)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateReviewEvidence(reviewBody, dispositionBody, implementationCommit); err == nil {
				t.Fatal("invalid review evidence was accepted")
			}
		})
	}
}

func TestValidateMaintainerAuthorizationEvidenceBindsFinalInputs(t *testing.T) {
	const implementationCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	binding := InputDigests{
		Catalog: "sha256:" + strings.Repeat("1", 64),
		Oracle:  "sha256:" + strings.Repeat("2", 64),
		Ratchet: "sha256:" + strings.Repeat("3", 64),
		Policy:  "sha256:" + strings.Repeat("4", 64),
	}
	approval, authorization := validMaintainerAuthorizationEvidence(implementationCommit, binding)
	approvalBody, err := json.Marshal(approval)
	if err != nil {
		t.Fatal(err)
	}
	authorizationBody, err := json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateMaintainerAuthorizationEvidence(approvalBody, authorizationBody, implementationCommit, binding); err != nil {
		t.Fatalf("valid maintainer authorization rejected: %v", err)
	}
	if err := validateReviewEvidenceWithBindings(approvalBody, authorizationBody, implementationCommit, binding); err != nil {
		t.Fatalf("versioned evidence policy did not select maintainer authorization: %v", err)
	}

	approval.Body = "decision: approved\nimplementation_commit: " + implementationCommit
	approvalBody, err = json.Marshal(approval)
	if err != nil {
		t.Fatal(err)
	}
	authorization.ApprovalDigest = sha256Digest(approvalBody)
	authorizationBody, err = json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateMaintainerAuthorizationEvidence(approvalBody, authorizationBody, implementationCommit, binding); err == nil {
		t.Fatal("maintainer authorization accepted a comment without frozen input digests")
	}

	for name, mutate := range map[string]func(*maintainerApprovalCapture, *maintainerAuthorizationCapture, *InputDigests){
		"unexpected pull request": func(approval *maintainerApprovalCapture, _ *maintainerAuthorizationCapture, _ *InputDigests) {
			approval.URL = "https://github.com/KKloudTarus/synapse-ce/pull/9999#issuecomment-1234"
		},
		"wrong head URL": func(approval *maintainerApprovalCapture, _ *maintainerAuthorizationCapture, _ *InputDigests) {
			approval.HeadURL = "https://github.com/KKloudTarus/synapse-ce/commit/" + strings.Repeat("b", 40)
		},
		"unapproved comment": func(approval *maintainerApprovalCapture, _ *maintainerAuthorizationCapture, _ *InputDigests) {
			approval.Decision = "pending"
		},
		"missing exact SHA in comment": func(approval *maintainerApprovalCapture, _ *maintainerAuthorizationCapture, _ *InputDigests) {
			approval.Body = "decision: approved"
		},
		"tampered comment": func(approval *maintainerApprovalCapture, _ *maintainerAuthorizationCapture, _ *InputDigests) {
			approval.Body += "\nextra"
		},
		"stale implementation": func(approval *maintainerApprovalCapture, authorization *maintainerAuthorizationCapture, _ *InputDigests) {
			authorization.ImplementationCommit = strings.Repeat("b", 40)
		},
		"candidate oracle": func(_ *maintainerApprovalCapture, _ *maintainerAuthorizationCapture, binding *InputDigests) {
			binding.Oracle = "sha256:" + strings.Repeat("5", 64)
		},
		"wrong ratchet": func(_ *maintainerApprovalCapture, authorization *maintainerAuthorizationCapture, _ *InputDigests) {
			authorization.RatchetDigest = "sha256:" + strings.Repeat("6", 64)
		},
		"missing transcription": func(_ *maintainerApprovalCapture, authorization *maintainerAuthorizationCapture, _ *InputDigests) {
			authorization.TranscribedBy = ""
		},
		"maintainer login mismatch": func(_ *maintainerApprovalCapture, authorization *maintainerAuthorizationCapture, _ *InputDigests) {
			authorization.MaintainerLogin = "other-maintainer"
		},
	} {
		t.Run(name, func(t *testing.T) {
			approval, authorization := validMaintainerAuthorizationEvidence(implementationCommit, binding)
			actualBinding := binding
			mutate(&approval, &authorization, &actualBinding)
			approvalBody, err := json.Marshal(approval)
			if err != nil {
				t.Fatal(err)
			}
			authorizationBody, err := json.Marshal(authorization)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateMaintainerAuthorizationEvidence(approvalBody, authorizationBody, implementationCommit, actualBinding); err == nil {
				t.Fatal("invalid maintainer authorization evidence was accepted")
			}
		})
	}
}

func TestMaintainerCommentBindsApprovalRejectsMissingConflictingAndDuplicateDigests(t *testing.T) {
	const implementationCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bindings := InputDigests{
		Catalog: "sha256:" + strings.Repeat("1", 64),
		Oracle:  "sha256:" + strings.Repeat("2", 64),
		Ratchet: "sha256:" + strings.Repeat("3", 64),
		Policy:  "sha256:" + strings.Repeat("4", 64),
	}
	approval, _ := validMaintainerAuthorizationEvidence(implementationCommit, bindings)
	if !maintainerCommentBindsApproval(strings.ReplaceAll(approval.Body, "\n", "\r\n"), implementationCommit, bindings) {
		t.Fatal("unchanged Windows line endings were rejected")
	}
	for _, body := range []string{approval.Body + "\n", strings.ReplaceAll(approval.Body, "\n", "\r\n") + "\r\n"} {
		if !maintainerCommentBindsApproval(body, implementationCommit, bindings) {
			t.Fatal("one terminal line ending was rejected")
		}
	}
	for name, body := range map[string]string{
		"missing":     strings.Replace(approval.Body, "\ncatalog_digest: "+bindings.Catalog, "", 1),
		"conflicting": strings.Replace(approval.Body, "catalog_digest: "+bindings.Catalog, "catalog_digest: sha256:"+strings.Repeat("5", 64), 1),
		"duplicate":   approval.Body + "\ncatalog_digest: " + bindings.Catalog,
		"extra":       approval.Body + "\nquoted example: decision: approved",
		"blank-line":  approval.Body + "\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			if maintainerCommentBindsApproval(body, implementationCommit, bindings) {
				t.Fatalf("%s digest line was accepted", name)
			}
		})
	}
}

func TestMaintainerAuthorizationUsesFinalReboundInputDigests(t *testing.T) {
	const implementationCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	finalBindings := InputDigests{
		Catalog: "sha256:" + strings.Repeat("1", 64),
		Oracle:  "sha256:" + strings.Repeat("2", 64),
		Ratchet: "sha256:" + strings.Repeat("3", 64),
		Policy:  "sha256:" + strings.Repeat("4", 64),
	}
	approval, authorization := validMaintainerAuthorizationEvidence(implementationCommit, finalBindings)
	approvalBody, err := json.Marshal(approval)
	if err != nil {
		t.Fatal(err)
	}
	authorizationBody, err := json.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for path, body := range map[string][]byte{
		"repository/reviews/github/approval.json":                   approvalBody,
		"repository/reviews/dispositions/github/authorization.json": authorizationBody,
	} {
		fullPath := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	preRebind := finalBindings
	preRebind.Catalog = "sha256:" + strings.Repeat("5", 64)
	state := runState{input: RunInput{TrustedInputRoot: root, ImplementationCommit: implementationCommit}, inputDigests: preRebind}
	if err := state.bindFinalReviewEvidence(); err == nil {
		t.Fatal("maintainer authorization accepted pre-rebind input digests")
	}
	state.inputDigests = finalBindings
	if err := state.bindFinalReviewEvidence(); err != nil {
		t.Fatalf("maintainer authorization rejected final rebound digests: %v", err)
	}
}

func validReviewEvidence(implementationCommit string) (reviewCapture, dispositionCapture) {
	const timestamp = "2026-09-21T00:00:00Z"
	review := reviewCapture{
		SchemaVersion: reviewCaptureSchemaVersion,
		ID:            "1234",
		URL:           "https://github.com/example-owner/example-repository/pull/321#pullrequestreview-1234",
		Login:         "reviewer",
		State:         "COMMENTED",
		SubmittedAt:   timestamp,
		CommitID:      implementationCommit,
		Body:          "reviewed",
	}
	return review, dispositionCapture{
		SchemaVersion:        dispositionCaptureSchemaVersion,
		ID:                   "5678",
		URL:                  "https://github.com/example-owner/example-repository/pull/321#issuecomment-5678",
		Login:                "maintainer",
		CreatedAt:            timestamp,
		UpdatedAt:            timestamp,
		ReviewID:             review.ID,
		ReviewedCommit:       review.CommitID,
		ImplementationCommit: implementationCommit,
		Decision:             "approved",
		Body:                 "accepted",
	}
}

func validMaintainerAuthorizationEvidence(implementationCommit string, bindings InputDigests) (maintainerApprovalCapture, maintainerAuthorizationCapture) {
	const timestamp = "2026-09-21T00:00:00Z"
	approval := maintainerApprovalCapture{
		SchemaVersion:        maintainerApprovalCaptureSchemaVersion,
		ID:                   "1234",
		URL:                  "https://github.com/KKloudTarus/synapse-ce/pull/1320#issuecomment-1234",
		HeadURL:              "https://github.com/KKloudTarus/synapse-ce/commit/" + implementationCommit,
		Login:                "maintainer",
		CreatedAt:            timestamp,
		UpdatedAt:            timestamp,
		Decision:             "approved",
		ImplementationCommit: implementationCommit,
		Body:                 canonicalMaintainerApprovalComment(implementationCommit, bindings),
	}
	approvalBody, err := json.Marshal(approval)
	if err != nil {
		panic(err)
	}
	return approval, maintainerAuthorizationCapture{
		SchemaVersion:        maintainerAuthorizationSchemaVersion,
		ApprovalID:           approval.ID,
		ApprovalDigest:       sha256Digest(approvalBody),
		MaintainerLogin:      approval.Login,
		ImplementationCommit: implementationCommit,
		CatalogDigest:        bindings.Catalog,
		OracleDigest:         bindings.Oracle,
		RatchetDigest:        bindings.Ratchet,
		PolicyDigest:         bindings.Policy,
		Decision:             "approved",
		TranscribedBy:        "evidence-bot",
		TranscribedAt:        timestamp,
		Body:                 "transcribed GitHub approval",
	}
}

func TestOwnedBuildInjectsStableBenchmarkVersion(t *testing.T) {
	_, source := testFixture(t, bench.EngineOwned)
	binaryName := "synapse-sca-bench"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(t.TempDir(), binaryName)
	repositoryRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", ownedBuildArguments(binaryPath)...)
	build.Dir = repositoryRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build owned benchmark helper: %v\n%s", err, output)
	}
	run := exec.Command(
		binaryPath,
		"--owned-helper",
		"-database", source.Database.Path,
		"-database-format", string(source.Database.Format),
		"-sbom", source.SBOMPath,
	)
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run owned benchmark helper: %v\n%s", err, output)
	}
	var wire ownedWire
	if err := json.Unmarshal(output, &wire); err != nil {
		t.Fatalf("decode owned benchmark output: %v", err)
	}
	if wire.EngineVersion != ownedBenchmarkVersion {
		t.Fatalf("owned engine version = %q, want %q", wire.EngineVersion, ownedBenchmarkVersion)
	}
}

func TestTrustedOwnedBuildArgumentsMatchCandidateDeterministicFlags(t *testing.T) {
	binaryPath := filepath.Join(t.TempDir(), "synapse-sca-bench")
	trusted := ownedBuildArguments(binaryPath)
	candidate := candidateOwnedBuildArguments(binaryPath)
	if strings.Join(trusted, "\x00") != strings.Join(candidate, "\x00") {
		t.Fatalf("trusted build arguments = %#v, want candidate parity %#v", trusted, candidate)
	}
	if strings.Join(ownedBuildEnvironment(), "\x00") != strings.Join(candidateOwnedBuildEnvironment(), "\x00") {
		t.Fatalf("trusted build environment = %#v, want candidate parity %#v", ownedBuildEnvironment(), candidateOwnedBuildEnvironment())
	}
}

func TestReduceRepetitionsRejectsFailedAbsoluteGate(t *testing.T) {
	corpusRoot := filepath.Join("..", "..", "usecase", "scabench", "corpus")
	catalog, err := decodeCatalogFile(filepath.Join(corpusRoot, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	oracle, err := decodeOracleFile(filepath.Join(corpusRoot, "oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	ratchet, err := decodeRatchetFile(filepath.Join(corpusRoot, "ratchet.json"))
	if err != nil {
		t.Fatal(err)
	}
	observations := make([]bench.Observation, 0, len(ratchet.Floors))
	for _, floor := range ratchet.Floors {
		expected := floor.Expected
		state := bench.ObservationComplete
		if floor.Mode == bench.FloorGateModeUnsupportedOnly {
			state = bench.ObservationUnsupported
		}
		observations = append(observations, bench.Observation{
			SchemaVersion: bench.ObservationSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: ratchet.CatalogDigest,
			Engine: expected.Engine, EngineVersion: expected.EngineVersion, EngineBinaryDigest: expected.EngineBinaryDigest,
			DatabaseBuild: expected.DatabaseBuild, DatabaseDigest: expected.DatabaseDigest,
			EnvironmentID: expected.EnvironmentID, EnvironmentDigest: expected.EnvironmentDigest,
			TargetID: expected.TargetID, TargetDigest: expected.TargetDigest, SBOMDigest: expected.SBOMDigest,
			State: state, RawOutputDigest: sha256Digest([]byte(expected.TargetID + "\x00" + string(expected.Engine))), ConfigDigest: expected.ConfigDigest,
			CapabilityKind: expected.CapabilityKind, CapabilityDigest: expected.CapabilityDigest,
		})
	}
	if _, _, _, err := reduceRepetitions(catalog, oracle, ratchet, [][]bench.Observation{observations, append([]bench.Observation(nil), observations...)}); err == nil {
		t.Fatal("trusted cycle accepted observations with a failed absolute ratchet gate")
	}
}

func TestFixedTemplatesMaterializeTrustedInputs(t *testing.T) {
	corpusRoot := filepath.Join("..", "..", "usecase", "scabench", "corpus")
	catalog, err := decodeCatalogFile(filepath.Join(corpusRoot, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	trustedRoot := t.TempDir()
	writeTrustedInputLayout(t, trustedRoot)
	state := runState{
		input:          RunInput{CorpusRoot: corpusRoot, TrustedInputRoot: trustedRoot},
		catalog:        catalog,
		workRoot:       t.TempDir(),
		expectedStates: make(map[string]bench.ObservationState),
	}
	templates, err := state.loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(templates); got != fixedMatrixCells {
		t.Fatalf("template count = %d, want %d", got, fixedMatrixCells)
	}
	catalogDigest, err := bench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	for _, template := range templates {
		t.Run(template.TargetID+"/"+string(template.Engine), func(t *testing.T) {
			target, ok := catalogTarget(catalog, template.TargetID)
			if !ok {
				t.Fatalf("template target %q is absent from catalog", template.TargetID)
			}
			template.Capability = nil
			manifest, err := state.materializeManifest(catalogDigest, target, template)
			if err != nil {
				t.Fatal(err)
			}
			for name, path := range map[string]string{
				"SBOM":                    manifest.SBOMPath,
				"database":                manifest.Database.Path,
				"environment attestation": manifest.EnvironmentAttestation.Path,
			} {
				if !filepath.IsAbs(path) || !pathBelowRoot(trustedRoot, path) {
					t.Fatalf("%s path %q is not an absolute trusted-input path", name, path)
				}
			}
			binaryLocator, databaseLocator := expectedTrustedInputLocators(t, template.TargetID, template.Engine)
			if manifest.Database.Path != filepath.Join(trustedRoot, databaseLocator) {
				t.Fatalf("database path = %q, want %q", manifest.Database.Path, filepath.Join(trustedRoot, databaseLocator))
			}
			if manifest.SBOMPath != filepath.Join(trustedRoot, "sboms", template.TargetID+".cdx.json") {
				t.Fatalf("SBOM path = %q", manifest.SBOMPath)
			}
			if manifest.EnvironmentAttestation.Path != filepath.Join(trustedRoot, "evidence-assets", "environment", "environment-attestation.json") {
				t.Fatalf("environment attestation path = %q", manifest.EnvironmentAttestation.Path)
			}
			if template.Engine == bench.EngineOwned {
				if manifest.Binary.Path != filepath.Join(state.workRoot, "tools", "synapse-sca-bench") || !filepath.IsAbs(manifest.Binary.Path) {
					t.Fatal("owned binary was not rebound to the absolute runtime work root")
				}
				return
			}
			if manifest.Binary.Path != filepath.Join(trustedRoot, binaryLocator) || !pathBelowRoot(trustedRoot, manifest.Binary.Path) {
				t.Fatalf("binary path = %q, want %q", manifest.Binary.Path, filepath.Join(trustedRoot, binaryLocator))
			}
		})
	}
}

func TestTrustedInputResolverRejectsUnsafeTemplatePaths(t *testing.T) {
	corpusRoot := filepath.Join("..", "..", "usecase", "scabench", "corpus")
	trustedRoot := t.TempDir()
	writeTrustedInputLayout(t, trustedRoot)
	state := runState{input: RunInput{CorpusRoot: corpusRoot, TrustedInputRoot: trustedRoot}, workRoot: t.TempDir()}
	templates, err := state.loadTemplates()
	if err != nil {
		t.Fatal(err)
	}
	template := templates[runCellKey("debian-12-13-slim-amd64", bench.EngineGrype)]
	template.Binary.Path = filepath.Join(trustedRoot, "..", "outside-binary")
	template.Database.Path = filepath.Join(trustedRoot, "..", "outside-database")
	template.EnvironmentAttestation.Path = filepath.Join(trustedRoot, "..", "outside-attestation")
	paths, err := state.resolveTrustedManifestPaths(template)
	if err != nil {
		t.Fatal(err)
	}
	if !pathBelowRoot(trustedRoot, paths.binary) || !pathBelowRoot(trustedRoot, paths.database) || !pathBelowRoot(trustedRoot, paths.environmentAttestation) {
		t.Fatal("unsafe template host paths escaped the trusted input root")
	}

	template.Binary.Reference = "binary:../../outside"
	if _, err := state.resolveTrustedManifestPaths(template); err == nil {
		t.Fatal("unrecognized binary identity was accepted")
	}
	template = templates[runCellKey("debian-12-13-slim-amd64", bench.EngineGrype)]
	template.TargetID = "../../outside"
	if _, err := state.resolveTrustedManifestPaths(template); err == nil {
		t.Fatal("traversing template target was accepted")
	}

	outside := filepath.Join(t.TempDir(), "grype")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(trustedRoot, "tools", "grype")
	if err := os.Remove(binary); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, binary); err != nil {
		t.Skipf("create symlink: %v", err)
	}
	template = templates[runCellKey("debian-12-13-slim-amd64", bench.EngineGrype)]
	if _, err := state.resolveTrustedManifestPaths(template); err == nil {
		t.Fatal("symlinked binary outside the trusted root was accepted")
	}
}

func TestCapabilitySourcesResolveOnlyTrustedLocators(t *testing.T) {
	trustedRoot := t.TempDir()
	for reference, identity := range fixedTrustedCapabilitySources {
		path := filepath.Join(trustedRoot, "repository", filepath.FromSlash(identity.locator))
		body := []byte(reference)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		state := runState{input: RunInput{TrustedInputRoot: trustedRoot}}
		source := capabilitySourceTemplate{Reference: reference, Locator: identity.locator, Digest: sha256Digest(body)}
		artifacts, err := state.capabilitySources([]capabilitySourceTemplate{source})
		if err != nil {
			t.Fatal(err)
		}
		if len(artifacts) != 1 || artifacts[0].Path != path || !pathBelowRoot(trustedRoot, artifacts[0].Path) {
			t.Fatalf("capability source = %+v, want trusted path %q", artifacts, path)
		}
		source.Locator = "../../outside"
		if _, err := state.capabilitySources([]capabilitySourceTemplate{source}); err == nil {
			t.Fatal("traversing capability locator was accepted")
		}
	}
}

func writeTrustedInputLayout(t *testing.T, root string) {
	t.Helper()
	for _, locator := range fixedTrustedSBOMLocators {
		writeTrustedInputFile(t, root, locator)
	}
	writeTrustedInputFile(t, root, trustedEnvironmentAttestationLocator)
	for _, input := range fixedTrustedCompetitorInputs {
		writeTrustedInputFile(t, root, input.binaryLocator)
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(input.databaseLocator)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range fixedTrustedOwnedInputs {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(input.databaseLocator)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

func writeTrustedInputFile(t *testing.T, root, locator string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(locator))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(locator), 0o600); err != nil {
		t.Fatal(err)
	}
}

func expectedTrustedInputLocators(t *testing.T, targetID string, engine bench.Engine) (string, string) {
	t.Helper()
	switch engine {
	case bench.EngineGrype:
		return "tools/grype", "databases/grype"
	case bench.EngineTrivy:
		return "tools/trivy", "databases/trivy"
	case bench.EngineOSVScanner:
		return "tools/osv-scanner", "databases/osv"
	case bench.EngineOwned:
		switch targetID {
		case "debian-12-13-slim-amd64":
			return "", "databases/owned-debian"
		case "sles-15-6-bci-base-45-31-amd64":
			return "", "databases/owned-sles"
		case "rhel-9-8-ubi-amd64":
			return "", "databases/owned-redhat"
		}
	}
	t.Fatalf("unexpected fixed template %q/%q", targetID, engine)
	return "", ""
}

func pathBelowRoot(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func TestBoundInputDigestsRefreshRuntimeBindingsAndExternalEvidence(t *testing.T) {
	catalog, _ := testFixture(t, bench.EngineGrype)
	state := runState{catalog: catalog, ratchet: bench.Ratchet{}, inputDigests: InputDigests{Catalog: "stale", Ratchet: "stale"}}
	state.bindReviewEvidence([]byte("review bytes"), []byte("disposition bytes"))
	if state.inputDigests.Review != sha256Digest(state.review) || state.inputDigests.Disposition != sha256Digest(state.disposition) {
		t.Fatal("review evidence digests do not bind the exact validated bytes")
	}
	if err := state.refreshBoundInputDigests(); err != nil {
		t.Fatal(err)
	}
	firstCatalog, firstRatchet := state.inputDigests.Catalog, state.inputDigests.Ratchet
	state.catalog.Revision = "runtime-rebound"
	state.ratchet.CatalogRevision = "runtime-rebound"
	if err := state.refreshBoundInputDigests(); err != nil {
		t.Fatal(err)
	}
	catalogDigest, err := bench.DigestCatalog(state.catalog)
	if err != nil {
		t.Fatal(err)
	}
	ratchetDigest, err := bench.DigestRatchet(state.ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if state.inputDigests.Catalog != catalogDigest || state.inputDigests.Ratchet != ratchetDigest || state.inputDigests.Catalog == firstCatalog || state.inputDigests.Ratchet == firstRatchet {
		t.Fatal("published input digests were not refreshed for runtime bindings")
	}
}

func TestCyclePlanUsesStableOpaqueKeysAndCanonicalPairs(t *testing.T) {
	catalog := bench.Catalog{Targets: []bench.Target{{ID: "target-a"}, {ID: "target-b"}}}
	state := runState{
		catalog:        catalog,
		manifests:      make(map[string]CaptureManifest),
		expectedStates: make(map[string]bench.ObservationState),
	}
	for _, target := range catalog.Targets {
		for _, engine := range bench.Engines() {
			key := runCellKey(target.ID, engine)
			state.manifests[key] = CaptureManifest{TargetID: target.ID, Engine: engine}
			state.expectedStates[key] = bench.ObservationComplete
		}
	}
	plan := state.cyclePlan()
	if len(plan) != len(catalog.Targets)*len(bench.Engines()) {
		t.Fatalf("plan cells = %d", len(plan))
	}
	for index, cell := range plan {
		target := catalog.Targets[index/len(bench.Engines())]
		engine := bench.Engines()[index%len(bench.Engines())]
		if want := runCellKey(target.ID, engine); cell.Key != want || cell.Cell.key != want || cell.Cell.manifest.TargetID != target.ID || cell.Cell.manifest.Engine != engine {
			t.Fatalf("plan[%d] = %#v, want target=%q engine=%q key=%q", index, cell, target.ID, engine, want)
		}
		if err := benchcycle.ValidateTwoPassCellKey(cell.Key); err != nil {
			t.Fatalf("plan[%d] key is not an opaque two-pass key: %v", index, err)
		}
	}
	pairs, err := benchcycle.ExecuteTwoPass(context.Background(), benchcycle.TwoPassPlan[cycleCell]{Cells: plan},
		func(_ context.Context, attempt benchcycle.Attempt[cycleCell]) (benchcycle.AttemptOutcome[struct{}], error) {
			return benchcycle.AttemptOutcome[struct{}]{Address: attempt.Address}, nil
		}, nil)
	if err != nil {
		t.Fatalf("execute keyed cycle plan: %v", err)
	}
	for index, pair := range pairs {
		if pair.Cell.Key != plan[index].Key || pair.Outcomes[0].Address != (benchcycle.AttemptAddress{CellKey: plan[index].Key, Repetition: 1}) || pair.Outcomes[1].Address != (benchcycle.AttemptAddress{CellKey: plan[index].Key, Repetition: 2}) {
			t.Fatalf("pair[%d] = %#v", index, pair)
		}
	}
}

func TestStoredCaptureBundlePreservesExactArtifactBytesAndCancellation(t *testing.T) {
	catalog, manifest := testFixture(t, bench.EngineGrype)
	captured, err := NewCapturer(&fakeRunner{result: ports.ToolResult{Stdout: []byte(`{"descriptor":{"name":"grype","version":"1.2.3"},"matches":[]}`)}}).Capture(context.Background(), catalog, manifest)
	if err != nil {
		t.Fatal(err)
	}
	state := runState{rawRunRoot: t.TempDir()}
	store, err := state.newEvidenceStore()
	if err != nil {
		t.Fatal(err)
	}
	path, err := state.storeBundle(context.Background(), store, benchcycle.AttemptAddress{CellKey: runCellKey(manifest.TargetID, manifest.Engine), Repetition: 1}, captured)
	if err != nil {
		t.Fatalf("store capture bundle: %v", err)
	}
	wantPath := filepath.Join(t.TempDir(), "direct")
	if err := WriteBundle(wantPath, captured); err != nil {
		t.Fatal(err)
	}
	got, err := bundleFileMapContext(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := bundleFileMapContext(context.Background(), wantPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("stored artifact count = %d, want %d", len(got), len(want))
	}
	for name, body := range want {
		if !bytes.Equal(got[name], body) {
			t.Fatalf("stored artifact %q differs from WriteBundle bytes", name)
		}
	}

	cancelledState := runState{rawRunRoot: t.TempDir()}
	cancelledStore, err := cancelledState.newEvidenceStore()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cancelledState.storeBundle(ctx, cancelledStore, benchcycle.AttemptAddress{CellKey: runCellKey(manifest.TargetID, manifest.Engine), Repetition: 1}, captured); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled bundle storage error = %v, want context cancellation", err)
	}
	entries, err := os.ReadDir(cancelledState.rawRunRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cancelled storage left raw artifacts: %v, %v", entries, err)
	}
}

func TestReadBoundedContextStopsDuringMultiChunkRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := &cancellingChunkReader{cancel: cancel}
	_, _, err := readBoundedContext(ctx, reader, 2*bundleReadBufferSize, 2*bundleReadBufferSize)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("bounded read error = %v, want context cancellation", err)
	}
	if reader.reads != 1 {
		t.Fatalf("bounded reader reads = %d, want cancellation before the second chunk", reader.reads)
	}
}

type cancellingChunkReader struct {
	cancel context.CancelFunc
	reads  int
}

func (reader *cancellingChunkReader) Read(buffer []byte) (int, error) {
	reader.reads++
	if reader.reads > 1 {
		return 0, io.EOF
	}
	for index := range buffer {
		buffer[index] = 'x'
	}
	reader.cancel()
	return len(buffer), nil
}

func TestEvidenceStoreLimitsMatchFixedBundleShape(t *testing.T) {
	if len(capabilitySourceReferences) != fixedCapabilitySourceArtifacts {
		t.Fatalf("capability source count = %d, want %d", len(capabilitySourceReferences), fixedCapabilitySourceArtifacts)
	}
	limits := evidenceStoreLimits()
	maxCaptureBytes := maxBundleArtifactBytes + int64(maxRawBundleArtifacts-1)*maxManifestBytes
	if limits.MaxArtifactBytes != maxBundleArtifactBytes {
		t.Fatalf("artifact limit = %d, want %d", limits.MaxArtifactBytes, maxBundleArtifactBytes)
	}
	if limits.MaxTotalBytes != int64(fixedMatrixCells*fixedRepetitions)*maxCaptureBytes {
		t.Fatalf("aggregate limit = %d, want %d", limits.MaxTotalBytes, int64(fixedMatrixCells*fixedRepetitions)*maxCaptureBytes)
	}
	if limits.MaxFiles != fixedMatrixCells*fixedRepetitions*maxRawBundleArtifacts {
		t.Fatalf("file limit = %d, want %d", limits.MaxFiles, fixedMatrixCells*fixedRepetitions*maxRawBundleArtifacts)
	}
}

func TestCyclePublicationCleansBeforeStageVerificationAndDoesNotOverwrite(t *testing.T) {
	state := testPublicationState(t)
	cleanupCalls := 0
	verified := false
	state.runtimeCleanup = func(context.Context) error {
		cleanupCalls++
		for _, path := range []string{state.workspace.RawRunRoot(), state.workspace.WorkRoot()} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				return fmt.Errorf("private state %q remains during runtime cleanup: %v", path, err)
			}
		}
		return nil
	}
	state.stageVerifier = func(_ context.Context, stage string, _ []benchcycle.FileIdentity) error {
		if !state.cleanup.RawRunRemoved || !state.cleanup.DockerCleaned {
			return errors.New("stage verification ran before cleanup")
		}
		if stage == state.input.OutputRoot {
			return errors.New("stage verification read the destination")
		}
		verified = true
		return nil
	}
	publication, err := state.beginPublication()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state.input.OutputRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state.input.OutputRoot, "existing.json"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit(context.Background()); err == nil {
		t.Fatal("publication overwrote an existing destination")
	}
	if !verified || cleanupCalls != 1 {
		t.Fatalf("verified=%t cleanup calls=%d, want true and one", verified, cleanupCalls)
	}
	body, err := os.ReadFile(filepath.Join(state.input.OutputRoot, "existing.json"))
	if err != nil || string(body) != "existing" {
		t.Fatalf("existing destination = %q, %v", body, err)
	}
}

func TestCyclePublicationFailureCleansPrivateStateOnce(t *testing.T) {
	state := testPublicationState(t)
	cleanupCalls := 0
	state.runtimeCleanup = func(context.Context) error {
		cleanupCalls++
		return errors.New("runtime cleanup failed")
	}
	state.stageVerifier = func(context.Context, string, []benchcycle.FileIdentity) error {
		t.Fatal("stage verifier ran after cleanup failure")
		return nil
	}
	publication, err := state.beginPublication()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("result")); err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit(context.Background()); err == nil {
		t.Fatal("publication succeeded after cleanup failure")
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", cleanupCalls)
	}
	for _, path := range []string{state.workspace.RawRunRoot(), state.workspace.WorkRoot(), state.input.OutputRoot} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("path %q remains after failed publication: %v", path, err)
		}
	}
}

func testPublicationState(t *testing.T) runState {
	t.Helper()
	rawRoot := t.TempDir()
	workspace, err := benchcycle.PrepareWorkspace(rawRoot, "run/attempt")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(workspace.RawRunRoot()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workspace.RawRunRoot(), []byte("raw"), 0o600); err != nil {
		t.Fatal(err)
	}
	return runState{
		input:           RunInput{OutputRoot: filepath.Join(t.TempDir(), "output")},
		workspace:       workspace,
		cleanupRequired: true,
	}
}

func completePublicationArtifacts() (bench.Catalog, map[string][]byte) {
	catalog := bench.Catalog{Targets: make([]bench.Target, 0, len(fixedTargetIDs))}
	files := make(map[string][]byte, expectedPublicationFileCount())
	for _, path := range fixedPublicationArtifactPaths {
		files[path] = []byte(path)
	}
	for _, targetID := range fixedTargetIDs {
		body := []byte("SBOM for " + targetID)
		catalog.Targets = append(catalog.Targets, bench.Target{
			ID:         targetID,
			SBOMDigest: bench.SHA256Digest(body),
		})
		files["sboms/"+targetID+".cdx.json"] = body
	}
	return catalog, files
}

func measuredCycleResult(ownedRecall float64) bench.Result {
	metrics := make([]bench.RunMetric, 0, len(fixedTargetIDs)*len(bench.Engines()))
	for _, targetID := range fixedTargetIDs {
		for _, engine := range bench.Engines() {
			recall := 1.0
			if engine == bench.EngineOwned {
				recall = ownedRecall
			}
			metrics = append(metrics, measuredCycleMetric(targetID, engine, recall))
		}
	}
	return bench.Result{
		Gate:       &bench.Gate{Passed: true},
		RunMetrics: metrics,
	}
}

func measuredCycleMetric(targetID string, engine bench.Engine, recall float64) bench.RunMetric {
	truePositives := 1
	falseNegatives := 0
	if recall < 1 {
		falseNegatives = 1
	}
	precision := 1.0
	return bench.RunMetric{
		Run: bench.RunIdentity{
			TargetID: targetID,
			Engine:   engine,
			State:    bench.ObservationComplete,
		},
		Metrics: bench.EngineResult{
			Engine:            engine,
			Covered:           truePositives + falseNegatives + 1,
			AffectedRelations: truePositives + falseNegatives,
			NegativeRelations: 1,
			TruePositives:     truePositives,
			FalseNegatives:    falseNegatives,
			MetricsComplete:   true,
			Precision:         &precision,
			Recall:            &recall,
		},
	}
}

func sourceTarget(t *testing.T, catalog bench.Catalog) bench.Target {
	t.Helper()
	if len(catalog.Targets) != 1 {
		t.Fatal("fixture catalog must contain exactly one target")
	}
	return catalog.Targets[0]
}
