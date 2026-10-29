package response

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ValidateTargetBinding binds scope authority to the action and stable fingerprint.
// Asset ownership and current process identity are checked by routing and telemetry.
func ValidateTargetBinding(action Action, target engagement.Target, f responsesaga.TargetFingerprint) error {
	if action.Kind == KindStopProcess && target.Kind != engagement.TargetProcess {
		return fmt.Errorf("%w: stop_process requires process scope", shared.ErrForbidden)
	}
	if target.Value != action.Target.String() {
		return fmt.Errorf("%w: authorization target does not match the response action", shared.ErrForbidden)
	}
	if err := target.Validate(); err != nil {
		return err
	}
	if err := f.Validate(); err != nil {
		return err
	}
	valid := false
	switch action.Kind {
	case KindIsolateHost:
		valid = f.Kind == responsesaga.FingerprintHost && f.HostID == action.Target
	case KindStopProcess:
		valid = target.Kind == engagement.TargetProcess && f.Kind == responsesaga.FingerprintProcess && f.ProcessEntityID == action.Target
	case KindQuarantineFile:
		valid = f.Kind == responsesaga.FingerprintFile && f.FilePath == action.Target.String()
	}
	if !valid {
		return fmt.Errorf("%w: response %s target fingerprint does not bind kind %s to target %s", shared.ErrForbidden, action.ID, action.Kind, action.Target)
	}
	return nil
}
