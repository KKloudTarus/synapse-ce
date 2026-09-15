package scabench

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type cycleMatrixSpec struct {
	SchemaVersion   string      `json:"schema_version"`
	ExecutionStatus string      `json:"execution_status"`
	Repetitions     int         `json:"repetitions"`
	Cells           []CycleCell `json:"cells"`
}

func TestCheckedInCycleMatrixSpecDeclaresCompleteMatrixWithoutFabricatedFreeze(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve cycle matrix spec path")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(source), "testdata", "cycle-matrix-spec.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec cycleMatrixSpec
	if err := strictDecode(bytes.NewReader(body), &spec); err != nil {
		t.Fatalf("decode matrix spec: %v", err)
	}
	if spec.SchemaVersion != "synapse-sca-benchmark-cycle-matrix-spec-v1" || spec.ExecutionStatus != "requires_fresh_source_and_oracle_freeze" {
		t.Fatalf("matrix spec status = %q/%q", spec.SchemaVersion, spec.ExecutionStatus)
	}
	if spec.Repetitions != 2 || len(spec.Cells) != 8 {
		t.Fatalf("matrix repetitions/cells = %d/%d, want 2/8", spec.Repetitions, len(spec.Cells))
	}
	completeDispatches, unsupportedRecords := 0, 0
	seen := make(map[string]struct{}, len(spec.Cells))
	for _, cell := range spec.Cells {
		if err := cell.Validate(); err != nil {
			t.Fatalf("matrix cell: %v", err)
		}
		key := cycleCellKey(cell.TargetID, cell.Engine)
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate matrix cell %q", key)
		}
		seen[key] = struct{}{}
		if cell.ExpectedState == ObservationComplete {
			completeDispatches += cell.ScannerDispatches * spec.Repetitions
		} else {
			unsupportedRecords += spec.Repetitions
			if cell.TargetID != "sles-15-6-bci-base-amd64" || cell.Engine != EngineOSVScanner || cell.ScannerDispatches != 0 {
				t.Fatalf("unsupported matrix cell = %+v", cell)
			}
		}
	}
	if completeDispatches != 14 || unsupportedRecords != 2 {
		t.Fatalf("matrix complete dispatches/unsupported records = %d/%d, want 14/2", completeDispatches, unsupportedRecords)
	}
}
