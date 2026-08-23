package fleetdesired

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNormalizeCapabilitiesCanonical(t *testing.T) {
	got, err := NormalizeCapabilities([]string{" telemetry.process ", "inventory.host", "telemetry.process", ""})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"inventory.host", "telemetry.process"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestNormalizeCapabilitiesBoundsRawAndCanonicalIndependently(t *testing.T) {
	duplicates := make([]string, MaxCapabilities+1)
	for i := range duplicates {
		duplicates[i] = "process"
	}
	got, err := NormalizeCapabilities(duplicates)
	if err != nil || len(got) != 1 || got[0] != "process" {
		t.Fatalf("benign duplicates should canonicalize: got=%v err=%v", got, err)
	}

	tooManyDistinct := make([]string, MaxCapabilities+1)
	for i := range tooManyDistinct {
		tooManyDistinct[i] = fmt.Sprintf("cap.%03d", i)
	}
	if _, err := NormalizeCapabilities(tooManyDistinct); err == nil {
		t.Fatal("expected distinct capability-count validation error")
	}

	tooManyInputs := make([]string, MaxCapabilityInputs+1)
	for i := range tooManyInputs {
		tooManyInputs[i] = "process"
	}
	if _, err := NormalizeCapabilities(tooManyInputs); err == nil {
		t.Fatal("expected raw input-count validation error")
	}
	if _, err := NormalizeCapabilities([]string{strings.Repeat("x", MaxCapabilityLen+1)}); err == nil {
		t.Fatal("expected capability-length validation error")
	}
	if _, err := NormalizeCapabilities([]string{"sensor\nexec"}); err == nil {
		t.Fatal("expected control-character validation error")
	}
	if _, err := NormalizeCapabilities([]string{string([]byte{0xff})}); err == nil {
		t.Fatal("expected invalid UTF-8 capability validation error")
	}
}

func TestSupportedAssetKind(t *testing.T) {
	if !SupportedAssetKind(asset.KindHost) || !SupportedAssetKind(asset.KindCluster) {
		t.Fatal("host and cluster must be supported desired-state subjects")
	}
	for _, kind := range []asset.Kind{asset.KindWorkload, asset.KindImage, asset.KindNamespace} {
		if SupportedAssetKind(kind) {
			t.Fatalf("unexpected desired-state subject kind accepted: %q", kind)
		}
	}
}

func validState(now time.Time) State {
	return State{
		TenantID: "tenant-1", AssetID: "asset-1", PolicyID: "policy-1", UpdatedBy: "operator-1", Version: 1,
		Capabilities: []string{"a", "z"}, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
}

func TestStateValidateRequiresCanonicalNonEmptyVersionedPolicy(t *testing.T) {
	now := time.Date(2026, 8, 19, 1, 2, 3, 0, time.UTC)
	state := validState(now)
	if err := state.Validate(); err != nil {
		t.Fatalf("valid state rejected: %v", err)
	}

	state = validState(now)
	state.PolicyID = ""
	if err := state.Validate(); err == nil {
		t.Fatal("expected empty policy id to be rejected")
	}
	state = validState(now)
	state.UpdatedBy = "   "
	if err := state.Validate(); err == nil {
		t.Fatal("expected blank actor to be rejected")
	}
	state = validState(now)
	state.Capabilities = []string{"z", "a"}
	if err := state.Validate(); err == nil {
		t.Fatal("expected non-canonical ordering to be rejected")
	}
	state = validState(now)
	state.Capabilities = nil
	if err := state.Validate(); err == nil {
		t.Fatal("expected empty policy to be rejected")
	}
	state = validState(now)
	state.Version = 0
	if err := state.Validate(); err == nil {
		t.Fatal("expected non-positive version to be rejected")
	}
}
