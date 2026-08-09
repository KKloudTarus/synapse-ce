package sca

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/platform/config"
)

// TestFPTriageModeConfigReachesService covers the composition wire that both binaries use: the
// normalized config string must reach the service's effective policy mode, and invalid input must fail
// closed. This catches type/alias drift at the composition boundary in addition to policy-level tests.
func TestFPTriageModeConfigReachesService(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want aiTriageMode
	}{
		{name: "default", env: "", want: aiTriageModeShadow},
		{name: "enforce", env: "  ENFORCE  ", want: aiTriageModeEnforce},
		{name: "invalid", env: "automatic", want: aiTriageModeShadow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SYNAPSE_FP_TRIAGE_MODE", tt.env)
			cfg := config.Load()
			service := &Service{}
			service.SetFPTriageMode(cfg.FPTriageMode)
			if service.fpTriageMode != tt.want {
				t.Fatalf("config mode %q reached service as %q, want %q", cfg.FPTriageMode, service.fpTriageMode, tt.want)
			}
		})
	}
}
