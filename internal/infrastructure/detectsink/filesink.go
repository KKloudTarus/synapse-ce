// Package detectsink provides the milestone-1 landing spot for the detections the agent-side engine
// (#422) emits: an append-only JSONL file on the host. Shipping detections to the control plane and
// sealing them as hash-chained evidence is issue #423; until then the agent records them locally so the
// pipeline is real end-to-end and nothing is silently dropped.
package detectsink

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// FileSink appends each detection as one JSON line. It is safe for concurrent Emit (the engine is
// single-goroutine today, but a sink that corrupts under concurrency would be a silent evidence loss).
type FileSink struct {
	mu sync.Mutex
	f  *os.File
}

var _ ports.DetectionSink = (*FileSink)(nil)

// New opens (creating parent dirs) the JSONL file for append. A sink that cannot open its file is an
// error, not a silent no-op: the engine must know its detections have nowhere to go.
func New(path string) (*FileSink, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: detection sink needs a file path", shared.ErrValidation)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("detection sink dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open detection sink: %w", err)
	}
	return &FileSink{f: f}, nil
}

// Emit writes one detection as a JSON line. The detection is validated first, so a malformed record
// never reaches the file.
func (s *FileSink) Emit(_ context.Context, d detection.Detection) error {
	if err := d.Validate(); err != nil {
		return fmt.Errorf("detection sink: refusing invalid detection: %w", err)
	}
	line, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("detection sink: marshal: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("detection sink: write: %w", err)
	}
	return nil
}

// Close closes the underlying file.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}
