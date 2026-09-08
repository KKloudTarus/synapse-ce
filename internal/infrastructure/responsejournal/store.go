package responsejournal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Store struct {
	dir string
	mu  sync.Mutex
}

type haltFence struct {
	Generation int64 `json:"generation"`
	Halted     bool  `json:"halted"`
}

var _ ports.ResponseExecutionJournal = (*Store)(nil)

func New(stateDir string) (*Store, error) {
	if strings.TrimSpace(stateDir) == "" {
		return nil, fmt.Errorf("%w: response execution journal directory is required", shared.ErrValidation)
	}
	return &Store{dir: filepath.Join(stateDir, "response-execution")}, nil
}

func (s *Store) LoadResponseExecution(ctx context.Context, attemptKey string) (fleetagent.ResponseExecutionJournalEntry, bool, error) {
	if err := ctx.Err(); err != nil {
		return fleetagent.ResponseExecutionJournalEntry{}, false, err
	}
	if strings.TrimSpace(attemptKey) == "" {
		return fleetagent.ResponseExecutionJournalEntry{}, false, fmt.Errorf("%w: response attempt key is required", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path(attemptKey))
	if errors.Is(err, os.ErrNotExist) {
		return fleetagent.ResponseExecutionJournalEntry{}, false, nil
	}
	if err != nil {
		return fleetagent.ResponseExecutionJournalEntry{}, false, fmt.Errorf("read response execution journal: %w", err)
	}
	entry, err := decodeEntry(data)
	if err != nil {
		return fleetagent.ResponseExecutionJournalEntry{}, false, err
	}
	if entry.Command.AttemptKey != attemptKey {
		return fleetagent.ResponseExecutionJournalEntry{}, false, fmt.Errorf("%w: response execution journal path does not match its attempt", shared.ErrForbidden)
	}
	return entry, true, nil
}

func (s *Store) ListResponseExecutions(ctx context.Context) ([]fleetagent.ResponseExecutionJournalEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list response execution journal: %w", err)
	}
	entries := make([]fleetagent.ResponseExecutionJournalEntry, 0, len(files))
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if file.IsDir() || file.Name() == "halt-fence.json" || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, file.Name()))
		if err != nil {
			return nil, fmt.Errorf("read response execution journal %s: %w", file.Name(), err)
		}
		entry, err := decodeEntry(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file.Name(), err)
		}
		if filepath.Base(s.path(entry.Command.AttemptKey)) != file.Name() {
			return nil, fmt.Errorf("%w: response execution journal filename does not match its attempt", shared.ErrForbidden)
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Command.AttemptKey < entries[j].Command.AttemptKey })
	return entries, nil
}

func (s *Store) SaveResponseExecution(ctx context.Context, entry fleetagent.ResponseExecutionJournalEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := entry.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal response execution journal: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeFile(s.path(entry.Command.AttemptKey), data); err != nil {
		return fmt.Errorf("persist response execution journal: %w", err)
	}
	return nil
}

func (s *Store) DeleteResponseExecution(ctx context.Context, attemptKey string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(attemptKey) == "" {
		return fmt.Errorf("%w: response attempt key is required", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.path(attemptKey)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete response execution journal: %w", err)
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open response execution journal directory: %w", err)
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync response execution journal directory: %w", err)
	}
	return nil
}

func (s *Store) path(attemptKey string) string {
	digest := sha256.Sum256([]byte(attemptKey))
	return filepath.Join(s.dir, hex.EncodeToString(digest[:])+".json")
}

func decodeEntry(data []byte) (fleetagent.ResponseExecutionJournalEntry, error) {
	var entry fleetagent.ResponseExecutionJournalEntry
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entry); err != nil {
		return fleetagent.ResponseExecutionJournalEntry{}, fmt.Errorf("decode response execution journal: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fleetagent.ResponseExecutionJournalEntry{}, fmt.Errorf("decode response execution journal: trailing content")
	}
	if err := entry.Validate(); err != nil {
		return fleetagent.ResponseExecutionJournalEntry{}, fmt.Errorf("validate response execution journal: %w", err)
	}
	return entry, nil
}

func (s *Store) CurrentResponseHaltFence(ctx context.Context) (int64, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fence, err := s.loadFenceLocked()
	return fence.Generation, fence.Halted, err
}

func (s *Store) RaiseResponseHaltFence(ctx context.Context, generation int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if generation <= 0 {
		return fmt.Errorf("%w: response halt generation must be positive", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fence, err := s.loadFenceLocked()
	if err != nil {
		return err
	}
	if generation > fence.Generation {
		fence.Generation = generation
	}
	fence.Halted = true
	data, err := json.Marshal(fence)
	if err != nil {
		return fmt.Errorf("marshal response halt fence: %w", err)
	}
	if err := writeFile(filepath.Join(s.dir, "halt-fence.json"), data); err != nil {
		return fmt.Errorf("persist response halt fence: %w", err)
	}
	return nil
}

func (s *Store) loadFenceLocked() (haltFence, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, "halt-fence.json"))
	if errors.Is(err, os.ErrNotExist) {
		return haltFence{}, nil
	}
	if err != nil {
		return haltFence{}, fmt.Errorf("read response halt fence: %w", err)
	}
	var fence haltFence
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fence); err != nil {
		return haltFence{}, fmt.Errorf("decode response halt fence: %w", err)
	}
	if fence.Generation < 0 {
		return haltFence{}, fmt.Errorf("%w: response halt fence generation is negative", shared.ErrValidation)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return haltFence{}, fmt.Errorf("decode response halt fence: trailing content")
	}
	return fence, nil
}

func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil && runtime.GOOS != "windows" {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".response-execution-*.tmp")
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
