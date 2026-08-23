package egressbroker

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var ErrGrantReplay = errors.New("egress grant was already used")

type GrantReplayStore interface {
	Consume(id string, expiresAt, now time.Time) error
}

type replayRecord struct {
	ID        string `json:"id"`
	ExpiresAt int64  `json:"expires_at"`
}

// FileGrantReplayStore is a root-owned append-only replay journal. A grant is
// synced before namespace setup begins, so a broker crash or restart cannot make
// an already presented grant reusable. Expired entries are ignored when loading.
type FileGrantReplayStore struct {
	mu          sync.Mutex
	path        string
	expectedUID int
	entries     map[string]time.Time
	syncFile    func(*os.File) error
	syncDir     func(string) error
}

func NewFileGrantReplayStore(path string, now time.Time) (*FileGrantReplayStore, error) {
	return newFileGrantReplayStore(path, now, 0)
}

func newFileGrantReplayStore(path string, now time.Time, expectedUID int) (*FileGrantReplayStore, error) {
	path = strings.TrimSpace(path)
	if !filepath.IsAbs(path) {
		return nil, errors.New("egress grant replay journal path must be absolute")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create egress grant replay directory: %w", err)
	}
	if err := validateReplayDirectory(dir, expectedUID); err != nil {
		return nil, err
	}
	store := &FileGrantReplayStore{
		path:        path,
		expectedUID: expectedUID,
		entries:     make(map[string]time.Time),
		syncFile:    func(file *os.File) error { return file.Sync() },
		syncDir:     syncReplayDirectory,
	}
	pathInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect egress grant replay journal: %w", err)
	}
	if err := validateReplayFile(pathInfo, expectedUID); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open egress grant replay journal: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat egress grant replay journal: %w", err)
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return nil, errors.New("egress grant replay journal changed while opening")
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 64<<10)
	for scanner.Scan() {
		record, err := decodeReplayRecord(scanner.Bytes())
		if err != nil {
			return nil, err
		}
		expiry := time.Unix(record.ExpiresAt, 0)
		if now.Before(expiry) {
			store.entries[record.ID] = expiry
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read egress grant replay journal: %w", err)
	}
	return store, nil
}

func (s *FileGrantReplayStore) Consume(id string, expiresAt, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = strings.TrimSpace(id)
	if id == "" || len(id) > 200 || !expiresAt.After(now) {
		return errors.New("invalid egress grant replay identity")
	}
	for existingID, expiry := range s.entries {
		if !now.Before(expiry) {
			delete(s.entries, existingID)
		}
	}
	if expiry, exists := s.entries[id]; exists && now.Before(expiry) {
		return ErrGrantReplay
	}
	if err := validateReplayDirectory(filepath.Dir(s.path), s.expectedUID); err != nil {
		return err
	}
	created := false
	if info, err := os.Lstat(s.path); errors.Is(err, os.ErrNotExist) {
		created = true
	} else if err != nil {
		return fmt.Errorf("inspect egress grant replay journal: %w", err)
	} else if err := validateReplayFile(info, s.expectedUID); err != nil {
		return err
	}
	record, err := json.Marshal(replayRecord{ID: id, ExpiresAt: expiresAt.Unix()})
	if err != nil {
		return fmt.Errorf("encode egress grant replay record: %w", err)
	}
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open egress grant replay journal: %w", err)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("stat opened egress grant replay journal: %w", err)
	}
	if err := validateReplayFile(openedInfo, s.expectedUID); err != nil {
		_ = file.Close()
		return err
	}
	pathInfo, err := os.Lstat(s.path)
	if err != nil || !os.SameFile(pathInfo, openedInfo) || pathInfo.Mode()&os.ModeSymlink != 0 {
		_ = file.Close()
		return errors.New("egress grant replay journal changed while opening")
	}
	written, writeErr := file.Write(append(record, '\n'))
	if writeErr == nil && written != len(record)+1 {
		writeErr = io.ErrShortWrite
	}
	if written > 0 {
		// Any uncertain append burns the grant in this process. A partial record makes
		// the next broker startup fail closed rather than silently accepting reuse.
		s.entries[id] = expiresAt
	}
	if writeErr != nil {
		_ = file.Close()
		return fmt.Errorf("append egress grant replay record: %w", writeErr)
	}
	if err := s.syncFile(file); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync egress grant replay journal: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close egress grant replay journal: %w", err)
	}
	if created {
		if err := s.syncDir(filepath.Dir(s.path)); err != nil {
			return fmt.Errorf("sync egress grant replay directory: %w", err)
		}
	}
	s.entries[id] = expiresAt
	return nil
}

func decodeReplayRecord(data []byte) (replayRecord, error) {
	var record replayRecord
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || strings.TrimSpace(record.ID) == "" || len(record.ID) > 200 {
		return replayRecord{}, errors.New("egress grant replay journal is malformed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return replayRecord{}, errors.New("egress grant replay journal is malformed")
	}
	return record, nil
}

func validateReplayDirectory(path string, expectedUID int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect egress grant replay directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("egress grant replay directory must be an owner-controlled directory")
	}
	if err := validateReplayOwner(info, expectedUID); err != nil {
		return fmt.Errorf("egress grant replay directory: %w", err)
	}
	return nil
}

func validateReplayFile(info os.FileInfo, expectedUID int) error {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("egress grant replay journal must be an owner-private regular file")
	}
	if err := validateReplayOwner(info, expectedUID); err != nil {
		return fmt.Errorf("egress grant replay journal: %w", err)
	}
	return nil
}

type memoryGrantReplayStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func newMemoryGrantReplayStore() *memoryGrantReplayStore {
	return &memoryGrantReplayStore{entries: make(map[string]time.Time)}
}

func (s *memoryGrantReplayStore) Consume(id string, expiresAt, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = strings.TrimSpace(id)
	if id == "" || !expiresAt.After(now) {
		return errors.New("invalid egress grant replay identity")
	}
	for existingID, expiry := range s.entries {
		if !now.Before(expiry) {
			delete(s.entries, existingID)
		}
	}
	if expiry, exists := s.entries[id]; exists && now.Before(expiry) {
		return ErrGrantReplay
	}
	s.entries[id] = expiresAt
	return nil
}
