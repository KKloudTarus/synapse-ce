package findinglineage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestCanonicalizeFingerprintV1GoldenVector(t *testing.T) {
	input := FingerprintCanonicalInputV1{
		CanonicalizationVersion:     CanonicalizationVersionV1,
		ProducerKind:                "sca",
		TargetIdentitySchemaVersion: 2,
		TargetIdentityCanonical:     "pkg:golang/example.com/mod",
		IdentityFields: map[string]CanonicalValue{
			"rule_id": Text("GO-2026-0001"),
			"symbols": StringSet("Zeta", "Alpha", "Alpha"),
			"nested": Object(map[string]CanonicalValue{
				"enabled": Boolean(true),
				"count":   Integer(2),
			}),
			"unicode": Text("e\u0301"),
		},
	}
	got, err := CanonicalizeFingerprintV1(input)
	if err != nil {
		t.Fatal(err)
	}
	wantCanonical := `{"canonicalization_version":1,"identity_fields":{"nested":{"count":2,"enabled":true},"rule_id":"GO-2026-0001","symbols":["Alpha","Zeta"],"unicode":"é"},"producer_kind":"sca","target_identity_canonical":"pkg:golang/example.com/mod","target_identity_schema_version":2}`
	if string(got.Bytes) != wantCanonical {
		t.Fatalf("canonical bytes\n got: %s\nwant: %s", got.Bytes, wantCanonical)
	}
	const wantFingerprint = "b05cad5e6b9c01a020e6e06ca81e311fc3a007c3d3207188c4300735bd89e274"
	if got.Fingerprint != wantFingerprint {
		t.Fatalf("fingerprint=%s want=%s", got.Fingerprint, wantFingerprint)
	}

	nfc := input
	nfc.IdentityFields = cloneCanonicalObject(input.IdentityFields)
	nfc.IdentityFields["unicode"] = Text("é")
	second, err := CanonicalizeFingerprintV1(nfc)
	if err != nil || second.Fingerprint != got.Fingerprint {
		t.Fatalf("NFC fingerprint=%s err=%v", second.Fingerprint, err)
	}
}

func TestCanonicalizeRejectsSensitiveTimestampAndEmptyValues(t *testing.T) {
	base := FingerprintCanonicalInputV1{
		CanonicalizationVersion:     CanonicalizationVersionV1,
		ProducerKind:                "sast",
		TargetIdentitySchemaVersion: 1,
		TargetIdentityCanonical:     "repo:example",
	}
	for name, testCase := range map[string]struct {
		fields map[string]CanonicalValue
		target error
	}{
		"sensitive": {map[string]CanonicalValue{"api_token": Text("redacted")}, ErrSensitiveInput},
		"timestamp": {map[string]CanonicalValue{"observed_at": Text("2026-08-31T00:00:00Z")}, ErrIncompleteIdentity},
		"empty":     {map[string]CanonicalValue{"rule_id": Text(" ")}, ErrIncompleteIdentity},
	} {
		t.Run(name, func(t *testing.T) {
			input := base
			input.IdentityFields = testCase.fields
			_, err := CanonicalizeFingerprintV1(input)
			if !errors.Is(err, testCase.target) {
				t.Fatalf("error=%v want=%v", err, testCase.target)
			}
		})
	}
}

func TestIdentityValidateRejectsSensitiveCanonicalJSON(t *testing.T) {
	identity := Identity{
		TenantID: "tenant", CycleID: "cycle", ID: "identity", FirstSeenSnapshotID: "snapshot",
		ProducerKind: "sca", FindingKind: "vulnerability", CanonicalizationVersion: 1,
		FingerprintSchemaVersion: 1, LineageFingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: "repo:example",
		CanonicalIdentityFields: []byte(`{"nested":{"api_token":"redacted"}}`), CreatedAt: time.Unix(1, 0).UTC(),
	}
	if err := identity.Validate(); !errors.Is(err, ErrSensitiveInput) {
		t.Fatalf("error=%v want=%v", err, ErrSensitiveInput)
	}
}

func TestIdentityAndObservationCannotCarryWorkflowState(t *testing.T) {
	banned := map[string]bool{
		"AcceptedRisk": true, "FalsePositive": true, "Remediation": true,
		"Assignee": true, "SLA": true, "VerificationState": true,
		"RawEvidence": true, "Password": true, "Token": true, "Credentials": true,
	}
	for _, value := range []any{Identity{}, Observation{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			if banned[typeOf.Field(index).Name] {
				t.Fatalf("%s exposes workflow field %s", typeOf.Name(), typeOf.Field(index).Name)
			}
		}
	}
}

func TestVerifyConformanceRejectsMissingMetadataAndUnprefixedHash(t *testing.T) {
	descriptor := MatcherDescriptor{
		ProducerKind: "sca", FindingKind: "vulnerability", Method: MethodMatcher, MethodVersion: 1,
		CanonicalizationVersion: 1, FingerprintSchemaVersion: 1, TargetIdentitySchemaVersion: 1,
	}
	input := FingerprintCanonicalInputV1{
		CanonicalizationVersion: 1, ProducerKind: "sca", TargetIdentitySchemaVersion: 1,
		TargetIdentityCanonical: "repo:example", IdentityFields: map[string]CanonicalValue{"rule_id": Text("GO-2026-0001")},
	}
	fingerprint, err := CanonicalizeFingerprintV1(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConformance(descriptor, []ConformanceVector{{Name: "valid", Input: input, ExpectedFingerprint: fingerprint.Fingerprint}}); err != nil {
		t.Fatal(err)
	}
	missing := input
	missing.ProducerKind = ""
	if err := VerifyConformance(descriptor, []ConformanceVector{{Name: "missing metadata", Input: missing, ExpectedFingerprint: fingerprint.Fingerprint}}); err == nil {
		t.Fatal("conformance accepted missing producer metadata")
	}
	rawDigest := sha256.Sum256(fingerprint.Bytes)
	if err := VerifyConformance(descriptor, []ConformanceVector{{Name: "unprefixed", Input: input, ExpectedFingerprint: hex.EncodeToString(rawDigest[:])}}); err == nil {
		t.Fatal("conformance accepted a hash without the lineage domain prefix")
	}
	sensitive := input
	sensitive.IdentityFields = map[string]CanonicalValue{"password": Text("redacted")}
	if err := VerifyConformance(descriptor, []ConformanceVector{{Name: "redaction", Input: sensitive, ExpectedError: ErrSensitiveInput}}); err != nil {
		t.Fatal(err)
	}
}
