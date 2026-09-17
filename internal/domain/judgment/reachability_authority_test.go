package judgment

import (
	"strings"
	"testing"
)

func TestArtifactAndSnapshotIdentityValidationAndMatching(t *testing.T) {
	source := authorityArtifact(t, "source", '1')
	sbom := authorityArtifact(t, "sbom", '2')
	run := authorityArtifact(t, "run", '3')
	snapshot, err := NewReachabilitySnapshotIdentity(source, sbom, run)
	if err != nil {
		t.Fatalf("NewReachabilitySnapshotIdentity() error = %v", err)
	}

	if !snapshot.Matches(source, sbom, run) {
		t.Fatal("snapshot must match its source, SBOM, and run identities")
	}
	if !snapshot.Equal(snapshot) {
		t.Fatal("snapshot must equal itself")
	}
	if err := snapshot.ValidateMatch(snapshot); err != nil {
		t.Fatalf("ValidateMatch() error = %v", err)
	}

	staleSource := authorityArtifact(t, "source", '4')
	stale, err := NewReachabilitySnapshotIdentity(staleSource, sbom, run)
	if err != nil {
		t.Fatalf("NewReachabilitySnapshotIdentity(stale) error = %v", err)
	}
	if snapshot.Equal(stale) || snapshot.Matches(staleSource, sbom, run) {
		t.Fatal("snapshot must not match a stale source identity")
	}
	if err := snapshot.ValidateMatch(stale); err == nil {
		t.Fatal("ValidateMatch() accepted a stale snapshot")
	}

	for _, test := range []struct {
		name   string
		id     string
		digest string
	}{
		{name: "empty id", id: "", digest: authorityDigest('a')},
		{name: "uppercase id", id: "Source", digest: authorityDigest('a')},
		{name: "uppercase digest", id: "source", digest: "sha256:" + repeatedByte('A', 64)},
		{name: "wrong algorithm", id: "source", digest: "sha512:" + repeatedByte('a', 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewArtifactIdentity(test.id, test.digest); err == nil {
				t.Fatal("NewArtifactIdentity() accepted invalid input")
			}
		})
	}
}

func TestInitialReachabilityAuthorityRegistryExactCoverageAndEligibleMapping(t *testing.T) {
	registry := authorityRegistry(t)

	expected := map[string]SuppressionDisposition{
		"go/source_tier2":            SuppressionEligible,
		"go/binary":                  SuppressionRaiseOnly,
		"python/import":              SuppressionEligible,
		"python/semantic":            SuppressionEligible,
		"dotnet/build_aware_import":  SuppressionEligible,
		"rust/import":                SuppressionProhibited,
		"ruby/import":                SuppressionProhibited,
		"javascript/import":          SuppressionRaiseOnly,
		"javascript/lexical":         SuppressionRaiseOnly,
		"javascript/interprocedural": SuppressionRaiseOnly,
		"rust/symbols_tier2":         SuppressionRaiseOnly,
		"php/import":                 SuppressionRaiseOnly,
		"php/symbols_tier2":          SuppressionRaiseOnly,
		"ruby/symbols_tier2":         SuppressionRaiseOnly,
		"dotnet/symbols_tier2":       SuppressionRaiseOnly,
		"c_cpp/symbols_tier2":        SuppressionRaiseOnly,
		"jvm/coarse":                 SuppressionRaiseOnly,
		"jvm/tier2":                  SuppressionRaiseOnly,
		"runtime/library_loads":      SuppressionRaiseOnly,
	}
	entries := registry.Policies()
	if len(entries) != len(expected) {
		t.Fatalf("registry has %d entries, want %d", len(entries), len(expected))
	}

	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		key := entry.Key().String()
		if seen[key] {
			t.Fatalf("registry repeated %q", key)
		}
		seen[key] = true
		if got, want := entry.Disposition(), expected[key]; got != want {
			t.Errorf("%s disposition = %q, want %q", key, got, want)
		}

		approval, approved := entry.Approval()
		if entry.Disposition() == SuppressionEligible {
			if !approved {
				t.Errorf("eligible %s has no approval metadata", key)
				continue
			}
			if !approval.Contract().Valid() {
				t.Errorf("eligible %s has an invalid completeness contract", key)
			}
			authority := approval.Authority()
			if authority.Kind != SuppressionAuthorityProcedural || authority.OriginAuthenticated {
				t.Errorf("eligible %s authority = %#v, want procedural and non-origin-authenticated", key, authority)
			}
			continue
		}
		if approved {
			t.Errorf("non-eligible %s carried approval metadata", key)
		}
	}
	for key := range expected {
		if !seen[key] {
			t.Errorf("registry missing %q", key)
		}
	}

	for _, test := range []struct {
		cohort   string
		mode     string
		proposer string
		verifier string
	}{
		{"go", "source_tier2", ProofActorCallgraphScan, ProofActorCallgraphEngine},
		{"python", "import", ProofActorPyImportScan, ProofActorPyImportEngine},
		{"python", "semantic", ProofActorPySemanticScan, ProofActorPySemanticEngine},
		{"dotnet", "build_aware_import", ProofActorDotNetReachScan, ProofActorDotNetReachEngine},
	} {
		policy, err := registry.Lookup(test.cohort, test.mode)
		if err != nil {
			t.Fatalf("Lookup(%q, %q) error = %v", test.cohort, test.mode, err)
		}
		approval, ok := policy.Approval()
		if !ok {
			t.Fatalf("Lookup(%q, %q) has no approval", test.cohort, test.mode)
		}
		if approval.Proposer() != test.proposer || approval.Verifier() != test.verifier {
			t.Errorf("Lookup(%q, %q) actors = %q/%q, want %q/%q", test.cohort, test.mode, approval.Proposer(), approval.Verifier(), test.proposer, test.verifier)
		}
	}
}

func TestInitialCompletenessContractsTreatUnavailableInputsAsIncomplete(t *testing.T) {
	registry := authorityRegistry(t)
	for _, test := range []struct{ cohort, mode string }{
		{cohort: "go", mode: "source_tier2"},
		{cohort: "python", mode: "import"},
		{cohort: "python", mode: "semantic"},
		{cohort: "dotnet", mode: "build_aware_import"},
	} {
		t.Run(test.cohort+"/"+test.mode, func(t *testing.T) {
			policy, err := registry.Lookup(test.cohort, test.mode)
			if err != nil {
				t.Fatalf("Lookup() error = %v", err)
			}
			approval, ok := policy.Approval()
			if !ok {
				t.Fatal("eligible policy has no approval metadata")
			}
			contract := approval.Contract()
			for _, obligation := range []CompletenessObligation{ObligationRuntimeInputs, ObligationDeployInputs} {
				values := contract.Obligations(obligation)
				if len(values) != 1 || !strings.Contains(values[0], "unavailability-makes-proof-incomplete") {
					t.Errorf("%s obligations = %q, want unavailable inputs to make proof incomplete", obligation, values)
				}
			}
		})
	}
}

func TestReachabilityAuthorityRegistryRejectsDuplicateAndUnknownKeys(t *testing.T) {
	registry := authorityRegistry(t)
	entries := registry.Policies()

	duplicate := append([]ReachabilityAuthorityPolicy(nil), entries...)
	duplicate[1] = entries[0]
	if _, err := NewReachabilityAuthorityRegistry(duplicate); err == nil {
		t.Fatal("NewReachabilityAuthorityRegistry() accepted duplicate coverage")
	}

	unknown := append([]ReachabilityAuthorityPolicy(nil), entries...)
	unknown[0].key = CohortModePolicyKey{cohort: "unknown", mode: "unknown"}
	if _, err := NewReachabilityAuthorityRegistry(unknown); err == nil {
		t.Fatal("NewReachabilityAuthorityRegistry() accepted an unknown key")
	}

	for _, test := range []struct{ cohort, mode string }{
		{cohort: "unknown", mode: "mode"},
		{cohort: "c_cpp", mode: "import"},
		{cohort: "dotnet", mode: "import"},
	} {
		if _, err := registry.Lookup(test.cohort, test.mode); err == nil {
			t.Errorf("Lookup(%q, %q) accepted unknown policy key", test.cohort, test.mode)
		}
	}
}

func TestInitialReachabilityAuthorityRegistryKeepsRaiseOnlyAndProhibitedPolicies(t *testing.T) {
	registry := authorityRegistry(t)
	for _, test := range []struct {
		cohort string
		mode   string
		want   SuppressionDisposition
	}{
		{cohort: "javascript", mode: "import", want: SuppressionRaiseOnly},
		{cohort: "javascript", mode: "lexical", want: SuppressionRaiseOnly},
		{cohort: "javascript", mode: "interprocedural", want: SuppressionRaiseOnly},
		{cohort: "php", mode: "import", want: SuppressionRaiseOnly},
		{cohort: "php", mode: "symbols_tier2", want: SuppressionRaiseOnly},
		{cohort: "rust", mode: "import", want: SuppressionProhibited},
		{cohort: "ruby", mode: "import", want: SuppressionProhibited},
		{cohort: "rust", mode: "symbols_tier2", want: SuppressionRaiseOnly},
		{cohort: "ruby", mode: "symbols_tier2", want: SuppressionRaiseOnly},
		{cohort: "dotnet", mode: "symbols_tier2", want: SuppressionRaiseOnly},
		{cohort: "c_cpp", mode: "symbols_tier2", want: SuppressionRaiseOnly},
		{cohort: "go", mode: "binary", want: SuppressionRaiseOnly},
		{cohort: "jvm", mode: "coarse", want: SuppressionRaiseOnly},
		{cohort: "jvm", mode: "tier2", want: SuppressionRaiseOnly},
		{cohort: "runtime", mode: "library_loads", want: SuppressionRaiseOnly},
	} {
		t.Run(test.cohort+"/"+test.mode, func(t *testing.T) {
			policy, err := registry.Lookup(test.cohort, test.mode)
			if err != nil {
				t.Fatalf("Lookup() error = %v", err)
			}
			if got := policy.Disposition(); got != test.want {
				t.Errorf("disposition = %q, want %q", got, test.want)
			}
			if _, ok := policy.Approval(); ok {
				t.Error("non-eligible policy carried approval metadata")
			}
		})
	}
}

func TestReachabilityAuthorityRegistryValidatesSuppressionIdentity(t *testing.T) {
	registry := authorityRegistry(t)
	policy, err := registry.Lookup("python", "semantic")
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	approval, ok := policy.Approval()
	if !ok {
		t.Fatal("eligible policy has no approval")
	}
	request := authorityRequest(t, approval)
	active := request.Snapshot
	if err := registry.ValidateSuppression("python", "semantic", active, request); err != nil {
		t.Fatalf("ValidateSuppression() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*SuppressionAuthorityRequest)
	}{
		{
			name: "wrong actor pair",
			mutate: func(request *SuppressionAuthorityRequest) {
				request.Verifier = ProofActorPyImportEngine
			},
		},
		{
			name: "stale contract digest",
			mutate: func(request *SuppressionAuthorityRequest) {
				request.ContractDigest = authorityDigest('f')
			},
		},
		{
			name: "stale contract id",
			mutate: func(request *SuppressionAuthorityRequest) {
				request.ContractID = "other-completeness-contract"
			},
		},
		{
			name: "stale source snapshot component",
			mutate: func(request *SuppressionAuthorityRequest) {
				request.Snapshot.source = authorityArtifact(t, "source", '4')
			},
		},
		{
			name: "stale SBOM snapshot component",
			mutate: func(request *SuppressionAuthorityRequest) {
				request.Snapshot.sbom = authorityArtifact(t, "sbom", '5')
			},
		},
		{
			name: "stale run snapshot component",
			mutate: func(request *SuppressionAuthorityRequest) {
				request.Snapshot.run = authorityArtifact(t, "run", '6')
			},
		},
		{
			name: "missing source snapshot component",
			mutate: func(request *SuppressionAuthorityRequest) {
				request.Snapshot.source = ArtifactIdentity{}
			},
		},
		{
			name: "missing SBOM snapshot component",
			mutate: func(request *SuppressionAuthorityRequest) {
				request.Snapshot.sbom = ArtifactIdentity{}
			},
		},
		{
			name: "missing run snapshot component",
			mutate: func(request *SuppressionAuthorityRequest) {
				request.Snapshot.run = ArtifactIdentity{}
			},
		},
		{
			name: "non-procedural authority",
			mutate: func(request *SuppressionAuthorityRequest) {
				request.Authority = SuppressionAuthority{Kind: "external"}
			},
		},
		{
			name: "claimed origin authentication",
			mutate: func(request *SuppressionAuthorityRequest) {
				request.Authority = SuppressionAuthority{Kind: SuppressionAuthorityProcedural, OriginAuthenticated: true}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := request
			test.mutate(&invalid)
			if err := registry.ValidateSuppression("python", "semantic", active, invalid); err == nil {
				t.Fatal("ValidateSuppression() accepted invalid authority evidence")
			}
		})
	}

	if _, err := NewSuppressionApproval(ProofActorPySemanticScan, ProofActorPySemanticScan, approval.Contract(), ProceduralSuppressionAuthority()); err == nil {
		t.Fatal("NewSuppressionApproval() accepted proposer equal to verifier")
	}
}

func TestCompletenessContractRejectsMissingObligationsAndTampering(t *testing.T) {
	definition := authorityContractDefinition()
	definition.Entrypoints = nil
	if _, err := NewCompletenessContract(definition); err == nil {
		t.Fatal("NewCompletenessContract() accepted missing entrypoint obligations")
	}

	contract, err := NewCompletenessContract(authorityContractDefinition())
	if err != nil {
		t.Fatalf("NewCompletenessContract() error = %v", err)
	}
	tampered := cloneCompletenessContract(contract)
	tampered.enumeration[0] = "different-enumeration"
	if tampered.Valid() {
		t.Fatal("CompletenessContract.Valid() accepted a tampered contract")
	}
	if _, err := NewSuppressionApproval(ProofActorPySemanticScan, ProofActorPySemanticEngine, tampered, ProceduralSuppressionAuthority()); err == nil {
		t.Fatal("NewSuppressionApproval() accepted a tampered contract")
	}
}

func TestCompletenessContractCanonicalDigestDoesNotRetainConstructionAliases(t *testing.T) {
	enumeration := []string{"module-enumeration"}
	definition := authorityContractDefinition()
	definition.Enumeration = enumeration
	first, err := NewCompletenessContract(definition)
	if err != nil {
		t.Fatalf("NewCompletenessContract(first) error = %v", err)
	}

	independent := authorityContractDefinition()
	independent.Enumeration = append([]string(nil), enumeration...)
	second, err := NewCompletenessContract(independent)
	if err != nil {
		t.Fatalf("NewCompletenessContract(second) error = %v", err)
	}
	if first.Digest() != second.Digest() {
		t.Fatalf("digest = %q, want deterministic equal digest %q", first.Digest(), second.Digest())
	}

	enumeration[0] = "mutated-after-construction"
	if !first.Valid() || first.Digest() != second.Digest() {
		t.Fatal("contract digest changed through a construction-slice alias")
	}
	obligations := first.Obligations(ObligationEnumeration)
	obligations[0] = "mutated-return-value"
	if got := first.Obligations(ObligationEnumeration)[0]; got != "module-enumeration" {
		t.Fatalf("Obligations() returned a mutable alias; got %q", got)
	}
}

func TestReachabilityAuthorityPolicyLeavesExistingClaimSuppressionUnchanged(t *testing.T) {
	claim := ReachabilityClaim{Reachable: NotReachable, Tier: Tier1}
	if !claim.SuppressesFinding() {
		t.Fatal("a representative Tier-1 not_reachable claim must remain a suppressing claim")
	}
}

func authorityRegistry(t *testing.T) ReachabilityAuthorityRegistry {
	t.Helper()
	registry, err := NewInitialReachabilityAuthorityRegistry()
	if err != nil {
		t.Fatalf("NewInitialReachabilityAuthorityRegistry() error = %v", err)
	}
	return registry
}

func authorityArtifact(t *testing.T, id string, digestByte byte) ArtifactIdentity {
	t.Helper()
	artifact, err := NewArtifactIdentity(id, authorityDigest(digestByte))
	if err != nil {
		t.Fatalf("NewArtifactIdentity(%q) error = %v", id, err)
	}
	return artifact
}

func authorityRequest(t *testing.T, approval SuppressionApproval) SuppressionAuthorityRequest {
	t.Helper()
	snapshot, err := NewReachabilitySnapshotIdentity(
		authorityArtifact(t, "source", '1'),
		authorityArtifact(t, "sbom", '2'),
		authorityArtifact(t, "run", '3'),
	)
	if err != nil {
		t.Fatalf("NewReachabilitySnapshotIdentity() error = %v", err)
	}
	contract := approval.Contract()
	return SuppressionAuthorityRequest{
		Snapshot:       snapshot,
		ContractID:     contract.ID(),
		ContractDigest: contract.Digest(),
		Proposer:       approval.Proposer(),
		Verifier:       approval.Verifier(),
		Authority:      approval.Authority(),
	}
}

func authorityContractDefinition() CompletenessContractDefinition {
	return CompletenessContractDefinition{
		ID:               "test-completeness-contract-v1",
		ReviewerRole:     "test-verifier-role",
		Enumeration:      []string{"module-enumeration"},
		Entrypoints:      []string{"application-entrypoints"},
		OpaqueSurface:    []string{"dynamic-surface-accounting"},
		RuntimeInputs:    []string{"runtime-inputs-declared"},
		DeploymentInputs: []string{"deployment-inputs-declared"},
	}
}

func authorityDigest(character byte) string {
	return "sha256:" + repeatedByte(character, 64)
}

func repeatedByte(character byte, count int) string {
	bytes := make([]byte, count)
	for index := range bytes {
		bytes[index] = character
	}
	return string(bytes)
}
