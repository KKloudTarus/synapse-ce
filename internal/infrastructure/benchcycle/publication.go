package benchcycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	publicationCopyBufferSize = 32 << 10
	// DefaultPublicationCleanupTimeout bounds terminal runtime cleanup independently of callers.
	DefaultPublicationCleanupTimeout = 30 * time.Second
	// MaxPublicationCleanupTimeout bounds per-publication cleanup timeout overrides.
	MaxPublicationCleanupTimeout = 10 * time.Minute
)

// PublicationLimits bounds the contents of one staged publication.
type PublicationLimits struct {
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxFiles      int
	// CleanupTimeout is the terminal cleanup limit; zero uses DefaultPublicationCleanupTimeout.
	CleanupTimeout time.Duration
}

// FileIdentity is the exact durable identity of one staged publication file.
type FileIdentity struct {
	Path   string
	Digest string
	Size   int64
}

// PublicationCleanup removes non-stage state before terminal verification.
type PublicationCleanup func(context.Context) error

// PublicationVerifier performs semantic verification against the final isolated stage.
type PublicationVerifier func(context.Context, string, []FileIdentity) error

// Publication stages a private output bundle before it is atomically published.
type Publication struct {
	mu sync.Mutex

	destination    string
	stage          string
	limits         PublicationLimits
	cleanup        PublicationCleanup
	verify         PublicationVerifier
	files          map[string]FileIdentity
	totalBytes     int64
	cleanupTimeout time.Duration
	state          publicationState

	cleanupStarted bool
	cleanupDone    chan struct{}
	cleanupErr     error
	terminalErr    error
}

type publicationState uint8

const (
	publicationActive publicationState = iota
	publicationCommitting
	publicationTerminating
	publicationCommitted
	publicationAborted
)

// BeginPublication creates a private staging directory beside an absent destination.
func BeginPublication(destination string, limits PublicationLimits, cleanup PublicationCleanup, verify PublicationVerifier) (*Publication, error) {
	if err := validatePublicationLimits(limits); err != nil {
		return nil, err
	}
	cleanupTimeout := limits.CleanupTimeout
	if cleanupTimeout == 0 {
		cleanupTimeout = DefaultPublicationCleanupTimeout
	}
	if err := ValidateAbsolutePath("publication destination", destination); err != nil {
		return nil, err
	}
	if cleanup == nil {
		return nil, errors.New("publication cleanup barrier is required")
	}
	if verify == nil {
		return nil, errors.New("publication verifier is required")
	}
	if err := EnsureAbsent(destination, "publication destination"); err != nil {
		return nil, err
	}
	parent, err := RealDirectory(filepath.Dir(destination))
	if err != nil {
		return nil, fmt.Errorf("validate publication parent: %w", err)
	}
	stage, err := os.MkdirTemp(parent, "."+filepath.Base(destination)+".stage-")
	if err != nil {
		return nil, fmt.Errorf("create publication stage: %w", err)
	}
	return &Publication{
		destination:    destination,
		stage:          stage,
		limits:         limits,
		cleanup:        cleanup,
		verify:         verify,
		files:          make(map[string]FileIdentity),
		cleanupTimeout: cleanupTimeout,
		state:          publicationActive,
	}, nil
}

// WriteBytes is a convenience wrapper for writing one in-memory publication file.
func (publication *Publication) WriteBytes(ctx context.Context, relative string, body []byte) (FileIdentity, error) {
	return publication.Write(ctx, relative, bytes.NewReader(body))
}

// Write streams one durable, exclusively created relative file to the private stage.
func (publication *Publication) Write(ctx context.Context, relative string, source io.Reader) (FileIdentity, error) {
	if publication == nil {
		return FileIdentity{}, errors.New("publication is required")
	}
	if ctx == nil {
		return FileIdentity{}, errors.New("publication context is required")
	}
	if err := ctx.Err(); err != nil {
		return FileIdentity{}, err
	}
	if source == nil {
		return FileIdentity{}, errors.New("publication source is required")
	}
	segments, err := publicationPathSegments(relative)
	if err != nil {
		return FileIdentity{}, err
	}

	publication.mu.Lock()
	defer publication.mu.Unlock()
	if publication.state != publicationActive {
		return FileIdentity{}, errors.New("publication is not writable")
	}
	if len(publication.files) >= publication.limits.MaxFiles {
		return FileIdentity{}, fmt.Errorf("publication exceeds %d file limit", publication.limits.MaxFiles)
	}
	if _, exists := publication.files[relative]; exists {
		return FileIdentity{}, fmt.Errorf("publication file %q already exists", relative)
	}
	if err := requireRealDirectory(publication.stage); err != nil {
		return FileIdentity{}, fmt.Errorf("validate publication stage: %w", err)
	}
	directory := publication.stage
	for _, segment := range segments[:len(segments)-1] {
		directory = filepath.Join(directory, segment)
		if err := createRealDirectory(directory); err != nil {
			return FileIdentity{}, fmt.Errorf("create publication directory: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return FileIdentity{}, err
	}

	path := filepath.Join(directory, segments[len(segments)-1])
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return FileIdentity{}, fmt.Errorf("create publication file: %w", err)
	}
	closed := false
	success := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if !success {
			_ = os.Remove(path)
		}
	}()

	identity, err := publication.writeFile(ctx, file, relative, source)
	if err != nil {
		return FileIdentity{}, err
	}
	if err := file.Close(); err != nil {
		return FileIdentity{}, fmt.Errorf("close publication file: %w", err)
	}
	closed = true
	if err := SyncDirectory(directory); err != nil {
		return FileIdentity{}, err
	}
	if err := ctx.Err(); err != nil {
		return FileIdentity{}, err
	}
	publication.files[relative] = identity
	publication.totalBytes += identity.Size
	success = true
	return identity, nil
}

func (publication *Publication) writeFile(ctx context.Context, file *os.File, relative string, source io.Reader) (FileIdentity, error) {
	hash := sha256.New()
	buffer := make([]byte, publicationCopyBufferSize)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return FileIdentity{}, err
		}
		read, readErr := source.Read(buffer)
		if read < 0 || read > len(buffer) {
			return FileIdentity{}, errors.New("publication source returned an invalid byte count")
		}
		if read > 0 {
			if err := ctx.Err(); err != nil {
				return FileIdentity{}, err
			}
			bytesRead := int64(read)
			if bytesRead > publication.limits.MaxFileBytes-size {
				return FileIdentity{}, fmt.Errorf("publication file %q exceeds %d byte limit", relative, publication.limits.MaxFileBytes)
			}
			if bytesRead > publication.limits.MaxTotalBytes-publication.totalBytes-size {
				return FileIdentity{}, fmt.Errorf("publication exceeds %d aggregate byte limit", publication.limits.MaxTotalBytes)
			}
			written, writeErr := file.Write(buffer[:read])
			if written < 0 || written > read {
				return FileIdentity{}, errors.New("publication file write returned an invalid byte count")
			}
			if writeErr != nil {
				return FileIdentity{}, fmt.Errorf("write publication file: %w", writeErr)
			}
			if written != read {
				return FileIdentity{}, io.ErrShortWrite
			}
			if _, err := hash.Write(buffer[:written]); err != nil {
				return FileIdentity{}, fmt.Errorf("hash publication file: %w", err)
			}
			size += bytesRead
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return FileIdentity{}, fmt.Errorf("read publication source: %w", readErr)
		}
		if read == 0 {
			return FileIdentity{}, io.ErrNoProgress
		}
	}
	if err := ctx.Err(); err != nil {
		return FileIdentity{}, err
	}
	if err := file.Sync(); err != nil {
		return FileIdentity{}, fmt.Errorf("sync publication file: %w", err)
	}
	return FileIdentity{Path: relative, Digest: fmt.Sprintf("%x", hash.Sum(nil)), Size: size}, nil
}

// Commit runs one cleanup barrier, verifies the final stage, and publishes without overwrite.
// A failed commit terminates the publication and cannot be retried.
func (publication *Publication) Commit(ctx context.Context) (err error) {
	if publication == nil {
		return errors.New("publication is required")
	}
	if err := publication.startCommit(); err != nil {
		return err
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if terminalErr := publication.terminate(); terminalErr != nil {
			err = errors.Join(err, terminalErr)
		}
	}()
	if ctx == nil {
		return errors.New("publication context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := publication.validateStage(ctx); err != nil {
		return err
	}
	if err := publication.runCleanup(); err != nil {
		return fmt.Errorf("run publication cleanup barrier: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	identities, err := publication.validateStage(ctx)
	if err != nil {
		return err
	}
	if err := publication.verify(ctx, publication.stage, cloneIdentities(identities)); err != nil {
		return fmt.Errorf("verify publication stage: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := publication.validateStage(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := PublishDirectory(publication.stage, publication.destination); err != nil {
		return err
	}
	publication.mu.Lock()
	publication.state = publicationCommitted
	publication.mu.Unlock()
	committed = true
	return nil
}

// Abort terminally runs cleanup and removes an unpublished stage. It never retries cleanup.
func (publication *Publication) Abort() error {
	if publication == nil {
		return errors.New("publication is required")
	}
	publication.mu.Lock()
	switch publication.state {
	case publicationActive:
		publication.state = publicationTerminating
		publication.mu.Unlock()
		return publication.terminate()
	case publicationAborted:
		err := publication.terminalErr
		publication.mu.Unlock()
		return err
	case publicationCommitted:
		publication.mu.Unlock()
		return errors.New("published publication cannot be aborted")
	default:
		publication.mu.Unlock()
		return errors.New("publication is already terminating")
	}
}

func (publication *Publication) startCommit() error {
	publication.mu.Lock()
	defer publication.mu.Unlock()
	if publication.state != publicationActive {
		return errors.New("publication is not committable")
	}
	publication.state = publicationCommitting
	return nil
}

func (publication *Publication) terminate() error {
	publication.mu.Lock()
	switch publication.state {
	case publicationCommitted:
		publication.mu.Unlock()
		return nil
	case publicationAborted:
		err := publication.terminalErr
		publication.mu.Unlock()
		return err
	default:
		publication.state = publicationTerminating
	}
	stage := publication.stage
	publication.mu.Unlock()

	cleanupErr := publication.runCleanup()
	stageErr := removeDirectory(stage)
	if stageErr != nil {
		stageErr = fmt.Errorf("remove publication stage: %w", stageErr)
	}
	terminalErr := errors.Join(cleanupErr, stageErr)
	publication.mu.Lock()
	publication.terminalErr = terminalErr
	publication.state = publicationAborted
	publication.mu.Unlock()
	return terminalErr
}

func (publication *Publication) runCleanup() error {
	publication.mu.Lock()
	if publication.cleanupStarted {
		done := publication.cleanupDone
		publication.mu.Unlock()
		<-done
		publication.mu.Lock()
		err := publication.cleanupErr
		publication.mu.Unlock()
		return err
	}
	publication.cleanupStarted = true
	publication.cleanupDone = make(chan struct{})
	done := publication.cleanupDone
	cleanup := publication.cleanup
	publication.mu.Unlock()

	cleanupContext, cancel := context.WithTimeout(context.Background(), publication.cleanupTimeout)
	err := cleanup(cleanupContext)
	cancel()

	publication.mu.Lock()
	publication.cleanupErr = err
	close(done)
	publication.mu.Unlock()
	return err
}

func (publication *Publication) validateStage(ctx context.Context) ([]FileIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := requireRealDirectory(publication.stage); err != nil {
		return nil, fmt.Errorf("validate publication stage: %w", err)
	}
	files := make([]FileIdentity, 0, len(publication.files))
	directories := make(map[string]struct{})
	var totalBytes int64
	err := filepath.WalkDir(publication.stage, func(location string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if location == publication.stage {
			return nil
		}
		info, err := os.Lstat(location)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(publication.stage, location)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if _, err := publicationPathSegments(relative); err != nil {
			return fmt.Errorf("unsafe publication stage path %q: %w", relative, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("publication stage path %q is a symlink", relative)
		}
		if info.IsDir() {
			directories[relative] = struct{}{}
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("publication stage path %q is not a regular file", relative)
		}
		if len(files) >= publication.limits.MaxFiles {
			return fmt.Errorf("publication exceeds %d file limit", publication.limits.MaxFiles)
		}
		identity, err := identityForPublicationFile(ctx, location, relative, publication.limits.MaxFileBytes, publication.limits.MaxTotalBytes-totalBytes)
		if err != nil {
			return err
		}
		totalBytes += identity.Size
		files = append(files, identity)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan publication stage: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("publication stage is empty")
	}
	sort.Slice(files, func(left, right int) bool { return files[left].Path < files[right].Path })
	if !sameDirectories(directories, publication.expectedDirectories()) {
		return nil, errors.New("publication stage directory set changed")
	}
	if !sameIdentities(files, publication.expectedIdentities()) {
		return nil, errors.New("publication stage file identities changed")
	}
	return files, nil
}

func identityForPublicationFile(ctx context.Context, location, relative string, fileLimit, totalLimit int64) (FileIdentity, error) {
	file, err := os.Open(location)
	if err != nil {
		return FileIdentity{}, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return FileIdentity{}, err
	}
	if !info.Mode().IsRegular() {
		return FileIdentity{}, errors.New("publication file is not regular")
	}
	hash := sha256.New()
	buffer := make([]byte, publicationCopyBufferSize)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return FileIdentity{}, err
		}
		read, readErr := file.Read(buffer)
		if read < 0 || read > len(buffer) {
			return FileIdentity{}, errors.New("publication file returned an invalid byte count")
		}
		if read > 0 {
			if err := ctx.Err(); err != nil {
				return FileIdentity{}, err
			}
			bytesRead := int64(read)
			if bytesRead > fileLimit-size {
				return FileIdentity{}, fmt.Errorf("publication stage file %q exceeds %d byte limit", relative, fileLimit)
			}
			if bytesRead > totalLimit-size {
				return FileIdentity{}, errors.New("publication stage exceeds aggregate byte limit")
			}
			if _, err := hash.Write(buffer[:read]); err != nil {
				return FileIdentity{}, fmt.Errorf("hash publication stage file: %w", err)
			}
			size += bytesRead
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return FileIdentity{}, fmt.Errorf("read publication stage file: %w", readErr)
		}
		if read == 0 {
			return FileIdentity{}, io.ErrNoProgress
		}
	}
	if err := ctx.Err(); err != nil {
		return FileIdentity{}, err
	}
	return FileIdentity{Path: relative, Digest: fmt.Sprintf("%x", hash.Sum(nil)), Size: size}, nil
}

func (publication *Publication) expectedIdentities() []FileIdentity {
	identities := make([]FileIdentity, 0, len(publication.files))
	for _, identity := range publication.files {
		identities = append(identities, identity)
	}
	sort.Slice(identities, func(left, right int) bool { return identities[left].Path < identities[right].Path })
	return identities
}

func (publication *Publication) expectedDirectories() map[string]struct{} {
	directories := make(map[string]struct{})
	for relative := range publication.files {
		segments := strings.Split(relative, "/")
		for index := 1; index < len(segments); index++ {
			directories[strings.Join(segments[:index], "/")] = struct{}{}
		}
	}
	return directories
}

func validatePublicationLimits(limits PublicationLimits) error {
	if limits.MaxFileBytes < 1 {
		return errors.New("publication file byte limit must be positive")
	}
	if limits.MaxTotalBytes < limits.MaxFileBytes {
		return errors.New("publication aggregate byte limit must cover one file")
	}
	if limits.MaxFiles < 1 {
		return errors.New("publication file limit must be positive")
	}
	if limits.CleanupTimeout < 0 || limits.CleanupTimeout > MaxPublicationCleanupTimeout {
		return fmt.Errorf("publication cleanup timeout must be between zero and %s", MaxPublicationCleanupTimeout)
	}
	return nil
}

func publicationPathSegments(relative string) ([]string, error) {
	if relative == "" || len(relative) > 512 || filepath.IsAbs(relative) || strings.Contains(relative, "\\") {
		return nil, fmt.Errorf("publication file path %q is unsafe", relative)
	}
	segments := strings.Split(relative, "/")
	for _, segment := range segments {
		if !PortableRunSegment(segment) {
			return nil, fmt.Errorf("publication file path %q is unsafe", relative)
		}
	}
	return segments, nil
}

func cloneIdentities(identities []FileIdentity) []FileIdentity {
	return append([]FileIdentity(nil), identities...)
}

func sameIdentities(left, right []FileIdentity) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameDirectories(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for directory := range left {
		if _, found := right[directory]; !found {
			return false
		}
	}
	return true
}
