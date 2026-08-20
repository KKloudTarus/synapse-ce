package fleetagent

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestTelemetryPriorityContract(t *testing.T) {
	tests := []struct {
		class detection.Class
		want  DeliveryPriority
	}{
		{detection.ClassProcess, PriorityP3},
		{detection.ClassNetwork, PriorityP3},
		{detection.ClassFile, PriorityP2},
		{detection.ClassPrivilege, PriorityP2},
	}
	for _, tt := range tests {
		got, err := TelemetryPriority(tt.class)
		if err != nil || got != tt.want {
			t.Errorf("TelemetryPriority(%s) = %s, %v; want %s", tt.class, got, err, tt.want)
		}
	}
	if _, err := TelemetryPriority("future"); err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown class error = %v", err)
	}
}
