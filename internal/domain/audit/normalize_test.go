package audit

import (
	"encoding/json"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNormalizeMetadataRoundTripsThroughJSON(t *testing.T) {
	in := map[string]string{"path": "a\xffb", "k\xfe": "v", "ok": "plain"}
	got, err := NormalizeMetadata(in)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]string
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(back, got) {
		t.Fatalf("stored %v, hashed %v: the stored form must be the hashed form", back, got)
	}
	at := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	for _, scheme := range []int{HashSchemeLegacy, HashSchemeFramed} {
		if ComputeHash(scheme, "", "a", "b", "c", got, at) != ComputeHash(scheme, "", "a", "b", "c", back, at) {
			t.Errorf("scheme %d: a row read back recomputes to a different hash", scheme)
		}
	}
	if in["path"] != "a\xffb" {
		t.Error("NormalizeMetadata must not mutate its input")
	}
}

func TestNormalizeMetadataLeavesValidInputAlone(t *testing.T) {
	in := map[string]string{"a": "b"}
	got, err := NormalizeMetadata(in)
	if err != nil || !maps.Equal(got, in) {
		t.Fatalf("got %v, %v", got, err)
	}
	if got, err := NormalizeMetadata(nil); err != nil || got != nil {
		t.Fatalf("nil metadata: got %v, %v", got, err)
	}
}

func TestNormalizeMetadataRefusesCollidingKeys(t *testing.T) {
	_, err := NormalizeMetadata(map[string]string{"a\xff": "1", "a\xfe": "2"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
}

func TestNormalizeText(t *testing.T) {
	if got := NormalizeText("a\xff\xfeb"); got != "a�b" {
		t.Errorf("NormalizeText = %q", got)
	}
	if got := NormalizeText("ok"); got != "ok" {
		t.Errorf("NormalizeText(valid) = %q", got)
	}
}
