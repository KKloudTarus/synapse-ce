package response

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

func TestProcessTargetBindingRequiresExactTypedIdentity(t *testing.T) {
	entity := telemetry.ProcessEntityID("asset", "boot", 123, 456)
	action, err := NewAction("stop", KindStopProcess, entity)
	if err != nil {
		t.Fatal(err)
	}
	target := engagement.Target{Kind: engagement.TargetProcess, Value: entity.String()}
	fingerprint := responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset", ProcessEntityID: entity}
	if err := ValidateTargetBinding(action, target, fingerprint); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []engagement.TargetKind{engagement.TargetCloudAccount, engagement.TargetRepo, engagement.TargetImage, engagement.TargetDomain, engagement.TargetIP, ""} {
		wrong := target
		wrong.Kind = kind
		if err := ValidateTargetBinding(action, wrong, fingerprint); err == nil {
			t.Errorf("accepted alias %q", kind)
		}
	}
	for _, other := range []struct {
		name  string
		boot  string
		pid   int
		start uint64
	}{
		{"reused PID", "boot", 123, 457}, {"reboot", "other-boot", 123, 456}, {"another process", "boot", 124, 456},
	} {
		t.Run(other.name, func(t *testing.T) {
			changed := fingerprint
			changed.ProcessEntityID = telemetry.ProcessEntityID("asset", shared.ID(other.boot), other.pid, other.start)
			if err := ValidateTargetBinding(action, target, changed); err == nil {
				t.Fatal("changed process incarnation accepted")
			}
		})
	}
}
