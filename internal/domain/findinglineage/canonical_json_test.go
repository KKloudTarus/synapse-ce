package findinglineage

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestCanonicalValueRetainedRoundTrip(t *testing.T) {
	input := FingerprintCanonicalInputV1{CanonicalizationVersion: 1, ProducerKind: "sca", TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: "repo:example", IdentityFields: map[string]CanonicalValue{
		"path": OrderedArray(Text("root"), Text("leaf")), "ids": StringSet("B", "A", "A"), "anchor": Object(map[string]CanonicalValue{"index": Integer(3), "direct": Boolean(true)}),
	}}
	before, err := CanonicalizeFingerprintV1(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var restored FingerprintCanonicalInputV1
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	after, err := CanonicalizeFingerprintV1(restored)
	if err != nil || before.Fingerprint != after.Fingerprint {
		t.Fatalf("retention changed identity: before=%s after=%s err=%v", before.Fingerprint, after.Fingerprint, err)
	}
}

func TestCanonicalValueRejectsInvalidRetainedValues(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{}`, `1.5`} {
		var value CanonicalValue
		if err := json.Unmarshal([]byte(raw), &value); err == nil {
			t.Fatalf("accepted invalid canonical value %s", raw)
		}
	}
}

func TestCanonicalValueRejectsSensitiveRetainedKey(t *testing.T) {
	// A boolean is a valid canonical value, but the sensitive field name must
	// still be rejected. No credential-shaped string is needed for this fixture.
	var value CanonicalValue
	err := json.Unmarshal([]byte(`{"password":true}`), &value)
	if !errors.Is(err, ErrSensitiveInput) {
		t.Fatalf("expected sensitive-key rejection, got %v", err)
	}
}
