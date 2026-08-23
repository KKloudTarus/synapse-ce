// Package agentstate persists small agent-control records which are separate from the append-only
// telemetry WAL.
package agentstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/KKloudTarus/synapse-ce/internal/platform/fssecurity"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const detectionStateFile = "detection-transport.json"

// DetectionStore persists the signing private key and crash-recovery batch coordinate under the
// service-owned state directory.
type DetectionStore struct{ path string }

// NewDetectionStore constructs a store rooted at the agent state directory.
func NewDetectionStore(dir string) *DetectionStore {
	return &DetectionStore{path: filepath.Join(dir, detectionStateFile)}
}

// Load returns ok=false only when no state has been created yet. Corrupt or unreadable state fails
// closed so an in-flight sequence or signing identity is never silently discarded.
func (s *DetectionStore) Load() (ports.DetectionDeliveryState, bool, error) {
	body, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return ports.DetectionDeliveryState{}, false, nil
	}
	if err != nil {
		return ports.DetectionDeliveryState{}, false, fmt.Errorf("read detection transport state: %w", err)
	}
	var state ports.DetectionDeliveryState
	if err := json.Unmarshal(body, &state); err != nil {
		return ports.DetectionDeliveryState{}, false, fmt.Errorf("decode detection transport state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return ports.DetectionDeliveryState{}, false, err
	}
	return state, true, nil
}

// Save writes the complete state with 0600 permissions. The file contains an Ed25519 private key and
// must be treated with the same protection as the long-lived fleet credential.
func (s *DetectionStore) Save(state ports.DetectionDeliveryState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create agent state directory: %w", err)
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode detection transport state: %w", err)
	}
	if err := writeDetectionState(s.path, body); err != nil {
		return fmt.Errorf("write detection transport state: %w", err)
	}
	return nil
}

// writeDetectionState syncs a complete replacement before publishing it. A crash can therefore leave
// either the old state or the new state at the canonical path, but never a truncated JSON document
// that loses an in-flight batch coordinate. The temp file is in the same directory so Rename is the
// atomic publication boundary; syncing that directory makes the renamed entry durable on Unix hosts.
func writeDetectionState(path string, body []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".detection-transport-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if fssecurity.UnixModeEnforced() {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if got := info.Mode().Perm(); got != 0o600 {
			return fmt.Errorf("detection state has mode %v, want 0600", got)
		}
		dir, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		if err := dir.Sync(); err != nil {
			_ = dir.Close()
			return err
		}
		if err := dir.Close(); err != nil {
			return err
		}
	}
	return nil
}

var _ ports.DetectionStateStore = (*DetectionStore)(nil)
