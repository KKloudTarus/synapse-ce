package spool

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
)

const stateVersion = 1

type diskState struct {
	Version         int                  `json:"version"`
	Generation      uint64               `json:"generation"`
	Session         fleetagent.SessionID `json:"session"`
	Boot            fleetagent.BootID    `json:"boot"`
	CurrentEpoch    uint64               `json:"current_epoch"`
	AssignedThrough [4]uint64            `json:"assigned_through"`
	ACK             map[string]uint64    `json:"ack"`
}

func newDiskState(session fleetagent.SessionID, boot fleetagent.BootID, epoch uint64) diskState {
	return diskState{
		Version: stateVersion, Session: session, Boot: boot, CurrentEpoch: epoch,
		ACK: make(map[string]uint64),
	}
}

func (s diskState) validate() error {
	if s.Version != stateVersion {
		return fmt.Errorf("unsupported spool state version %d", s.Version)
	}
	if s.Session == "" || s.Boot == "" || s.CurrentEpoch == 0 {
		return errors.New("spool state has an invalid identity or epoch")
	}
	for key := range s.ACK {
		if _, _, err := parseACKKey(key); err != nil {
			return fmt.Errorf("spool state has invalid ACK key: %w", err)
		}
	}
	return nil
}

func ackKey(priority fleetagent.DeliveryPriority, epoch uint64) string {
	return strconv.Itoa(int(priority)) + ":" + strconv.FormatUint(epoch, 10)
}

func parseACKKey(key string) (fleetagent.DeliveryPriority, uint64, error) {
	var p int
	var epoch uint64
	if _, err := fmt.Sscanf(key, "%d:%d", &p, &epoch); err != nil {
		return 0, 0, err
	}
	priority := fleetagent.DeliveryPriority(p)
	if !priority.Valid() || epoch == 0 || key != ackKey(priority, epoch) {
		return 0, 0, fmt.Errorf("malformed coordinate %q", key)
	}
	return priority, epoch, nil
}

func loadState(dir string) (diskState, bool, error) {
	primary, primaryErr := readStateFile(filepath.Join(dir, "state.json"))
	backup, backupErr := readStateFile(filepath.Join(dir, "state.backup.json"))

	switch {
	case primaryErr == nil && backupErr == nil:
		if backup.Generation > primary.Generation {
			return backup, true, nil
		}
		return primary, true, nil
	case primaryErr == nil:
		return primary, true, nil
	case backupErr == nil:
		return backup, true, nil
	case errors.Is(primaryErr, os.ErrNotExist) && errors.Is(backupErr, os.ErrNotExist):
		return diskState{}, false, nil
	default:
		return diskState{}, false, fmt.Errorf("read spool state (primary: %v; backup: %v)", primaryErr, backupErr)
	}
}

func readStateFile(path string) (diskState, error) {
	if err := securePath(path, 0o600); err != nil {
		return diskState{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return diskState{}, err
	}
	defer func() { _ = f.Close() }()
	limited := io.LimitReader(f, 1<<20)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var state diskState
	if err := decoder.Decode(&state); err != nil {
		return diskState{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return diskState{}, errors.New("spool state contains multiple JSON values")
		}
		return diskState{}, fmt.Errorf("spool state has trailing data: %w", err)
	}
	if err := state.validate(); err != nil {
		return diskState{}, err
	}
	return state, nil
}

func persistState(dir string, state *diskState) error {
	state.Generation++
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		state.Generation--
		return fmt.Errorf("encode spool state: %w", err)
	}
	data = append(data, '\n')
	tmp := filepath.Join(dir, ".state.json.tmp")
	if err := writeSyncedFile(tmp, data, 0o600); err != nil {
		state.Generation--
		return err
	}
	primary := filepath.Join(dir, "state.json")
	backup := filepath.Join(dir, "state.backup.json")
	if err := replaceFile(primary, backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		state.Generation--
		_ = os.Remove(tmp)
		return fmt.Errorf("rotate spool state: %w", err)
	}
	if err := replaceFile(tmp, primary); err != nil {
		state.Generation--
		return fmt.Errorf("install spool state: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync spool state directory: %w", err)
	}
	return nil
}

func writeSyncedFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if err := securePath(path, mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// replaceFile has its platform-specific implementation because Windows does
// not let os.Rename replace an existing destination.
func replaceFile(from, to string) error { return replaceFilePlatform(from, to) }
