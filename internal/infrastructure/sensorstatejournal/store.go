package sensorstatejournal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/sensorstateship"
)

var _ sensorstateship.StateStore = (*Store)(nil)

type Store struct {
	path string
}

func New(stateDir string) (*Store, error) {
	if stateDir == "" {
		return nil, fmt.Errorf("%w: sensor-state journal directory is required", shared.ErrValidation)
	}
	return &Store{path: filepath.Join(stateDir, "sensor-state-reports", "pending.json")}, nil
}

func (s *Store) Load(ctx context.Context) (sensorstateship.DeliveryState, error) {
	if err := ctx.Err(); err != nil {
		return sensorstateship.DeliveryState{}, err
	}
	state := sensorstateship.DeliveryState{Version: sensorstateship.DeliveryStateVersion}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return sensorstateship.DeliveryState{}, fmt.Errorf("sensor-state journal: read: %w", err)
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return sensorstateship.DeliveryState{}, fmt.Errorf("sensor-state journal: decode: %w", err)
	}
	if err := sensorstateship.ValidateDeliveryState(state); err != nil {
		return sensorstateship.DeliveryState{}, fmt.Errorf("sensor-state journal: %w", err)
	}
	return state, nil
}

func (s *Store) Save(ctx context.Context, state sensorstateship.DeliveryState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := sensorstateship.ValidateDeliveryState(state); err != nil {
		return fmt.Errorf("sensor-state journal: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("sensor-state journal: marshal: %w", err)
	}
	if err := writeFile(s.path, data); err != nil {
		return fmt.Errorf("sensor-state journal: persist: %w", err)
	}
	return nil
}

func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil && runtime.GOOS != "windows" {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sensor-state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
	if err := replaceFile(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}
