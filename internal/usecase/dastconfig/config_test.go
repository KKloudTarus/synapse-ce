package dastconfig

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestDecodeRejectsAmbiguousOrUnknownFields(t *testing.T) {
	for _, input := range []string{
		`{"target":"a","target":"b"}`,
		`{"session":{"scheme":"a","scheme":"b"}}`,
		`{"unknown":1}`,
		`{} {}`,
	} {
		if _, _, _, err := Decode([]byte(input), DefaultScanCeilings()); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("Decode(%q): %v", input, err)
		}
	}
}
