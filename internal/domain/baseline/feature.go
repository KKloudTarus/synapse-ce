package baseline

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Feature is one behavioral dimension observed per entity/peer-group over a window. The set is FIXED and
// ORDERED (an array index, not a map key) so a baseline summary and anomaly score are deterministic — no
// map iteration in any output. New features append at the end; existing indices never change.
type Feature int

const (
	// FeatureProcessSpawnRate: process spawns observed in the window.
	FeatureProcessSpawnRate Feature = iota
	// FeatureNetworkFanout: distinct network peers contacted in the window.
	FeatureNetworkFanout
	// FeatureNewExecPaths: distinct exec paths not seen before in the window.
	FeatureNewExecPaths
	// FeaturePrivilegeEvents: setuid/setresuid/capset events in the window.
	FeaturePrivilegeEvents
	// FeatureFileWriteBreadth: distinct files written in the window.
	FeatureFileWriteBreadth
	// numFeatures is the array size — keep last.
	numFeatures = iota
)

// NumFeatures is the number of behavioral features in an Observation vector — the exact length a caller
// (e.g. a persistence layer rehydrating via NewBaselineFrom) must provide.
const NumFeatures = numFeatures

// featureNames gives each feature a stable name for reasons/validation messages, indexed by Feature.
var featureNames = [numFeatures]string{
	"process_spawn_rate",
	"network_fanout",
	"new_exec_paths",
	"privilege_events",
	"file_write_breadth",
}

// Name returns the stable name of the feature (empty for an out-of-range value).
func (f Feature) Name() string {
	if f < 0 || int(f) >= numFeatures {
		return ""
	}
	return featureNames[f]
}

// MaxFeatureValue is the enforced upper bound on any per-window feature count. It is a real invariant, not
// a comment: together with MaxObservations it keeps every product in the anomaly math (and the int64
// sum/sumSq accumulators) far below overflow, and a per-window count above a million is itself pathological
// (clamp/reject rather than trust it). MaxObservations * MaxFeatureValue^2 stays well under MaxInt64.
const MaxFeatureValue int64 = 1_000_000

// Observation is one window's behavioral counts for an entity/peer-group — a fixed-size, ordered vector
// of bounded non-negative integer feature values. Integer (not float) keeps the fold deterministic.
type Observation struct {
	Values [numFeatures]int64
}

// Validate enforces non-negative, bounded feature values (counts cannot be negative, and are capped at
// MaxFeatureValue so the deterministic anomaly math cannot overflow — an unbounded count is rejected, never
// silently wrapped).
func (o Observation) Validate() error {
	for f := 0; f < numFeatures; f++ {
		v := o.Values[f]
		if v < 0 {
			return fmt.Errorf("%w: observation feature %s is negative (%d)", shared.ErrValidation, Feature(f).Name(), v)
		}
		if v > MaxFeatureValue {
			return fmt.Errorf("%w: observation feature %s value %d exceeds max %d", shared.ErrValidation, Feature(f).Name(), v, MaxFeatureValue)
		}
	}
	return nil
}
