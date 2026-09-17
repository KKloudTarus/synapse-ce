package benchmark

import (
	"bytes"
	"strings"
	"testing"
)

func TestStrictDecodeRejectsAmbiguousAndBoundedDocuments(t *testing.T) {
	type input struct {
		Value string `json:"value"`
	}
	for _, tc := range []struct {
		name string
		json string
	}{
		{name: "unknown field", json: `{"unknown":"value"}`},
		{name: "duplicate key", json: `{"value":"first","value":"second"}`},
		{name: "trailing value", json: `{"value":"first"} {"value":"second"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got input
			if err := StrictDecode(strings.NewReader(tc.json), &got); err == nil {
				t.Fatal("StrictDecode accepted an ambiguous document")
			}
		})
	}
	if err := ValidateJSONDocument(strings.NewReader(strings.Repeat(" ", int(MaxJSONBytes)+1))); err == nil {
		t.Fatal("ValidateJSONDocument accepted oversized input")
	}
}

func TestCanonicalJSONDigestAndWriteAreStable(t *testing.T) {
	left, err := CanonicalJSON(map[string]any{"b": 2, "a": []string{"x", "y"}})
	if err != nil {
		t.Fatal(err)
	}
	right, err := CanonicalJSON(map[string]any{"a": []string{"x", "y"}, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) || SHA256Digest(left) != SHA256Digest(right) {
		t.Fatalf("canonical identity drifted: %q / %q", left, right)
	}
	var output bytes.Buffer
	if err := WriteCanonicalJSON(&output, left); err != nil {
		t.Fatal(err)
	}
	if output.String() != string(left)+"\n" {
		t.Fatalf("canonical output = %q", output.String())
	}
}
