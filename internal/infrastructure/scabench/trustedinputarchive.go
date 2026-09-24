package scabench

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

// CollectTrustedInputArchive snapshots an already-prepared trusted input root into the archive CAS.
// It does not fetch, transform, or prepare inputs; the binding spec supplies the audited mapping from
// catalog origin pins to their materialized file or directory locations.
func CollectTrustedInputArchive(ctx context.Context, catalog bench.Catalog, spec bench.TrustedInputBindingSpec, trustedRoot string, store *PinArchiveStore) (bench.TrustedInputArchive, error) {
	if store == nil {
		return bench.TrustedInputArchive{}, errors.New("pin archive store is required")
	}
	if err := spec.Validate(catalog); err != nil {
		return bench.TrustedInputArchive{}, fmt.Errorf("validate trusted input binding spec: %w", err)
	}
	root, err := existingTrustedInputRoot(trustedRoot, false)
	if err != nil {
		return bench.TrustedInputArchive{}, err
	}
	inventory, err := inventoryTrustedInputRoot(ctx, root, store)
	if err != nil {
		return bench.TrustedInputArchive{}, err
	}
	if err := verifyTrustedInputBindings(ctx, root, spec.Bindings); err != nil {
		return bench.TrustedInputArchive{}, err
	}
	archive, err := bench.NewTrustedInputArchive(catalog, spec, inventory)
	if err != nil {
		return bench.TrustedInputArchive{}, fmt.Errorf("create trusted input archive: %w", err)
	}
	return archive, nil
}

// RestoreTrustedInputArchive materializes an archive into an existing, real, empty destination root.
// Every blob is streamed and rehashed before publication, then the reconstructed inventory and each
// catalog binding are independently checked before the destination is accepted.
func RestoreTrustedInputArchive(ctx context.Context, catalog bench.Catalog, spec bench.TrustedInputBindingSpec, archive bench.TrustedInputArchive, destinationRoot string, store *PinArchiveStore) error {
	if store == nil {
		return errors.New("pin archive store is required")
	}
	if err := archive.ValidateForCatalog(catalog, spec); err != nil {
		return fmt.Errorf("validate trusted input archive: %w", err)
	}
	root, err := existingTrustedInputRoot(destinationRoot, true)
	if err != nil {
		return err
	}
	for _, entry := range archive.Inventory {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Kind != bench.TrustedInputInventoryDirectory {
			continue
		}
		if err := createTrustedInputDirectory(root, entry); err != nil {
			return err
		}
	}
	for _, entry := range archive.Inventory {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Kind != bench.TrustedInputInventoryFile {
			continue
		}
		if err := restoreTrustedInputFile(ctx, root, entry, store); err != nil {
			return err
		}
	}
	// Directory permissions are applied after members are present so a valid read-only directory does
	// not prevent reconstruction of its children.
	for index := len(archive.Inventory) - 1; index >= 0; index-- {
		entry := archive.Inventory[index]
		if entry.Kind != bench.TrustedInputInventoryDirectory {
			continue
		}
		if err := setTrustedInputDirectoryMode(root, entry); err != nil {
			return err
		}
	}
	actual, err := inventoryTrustedInputRoot(ctx, root, nil)
	if err != nil {
		return fmt.Errorf("verify restored trusted input inventory: %w", err)
	}
	if !reflect.DeepEqual(actual, archive.Inventory) {
		return errors.New("restored trusted input inventory does not match archive manifest")
	}
	if err := verifyTrustedInputBindings(ctx, root, archive.Bindings); err != nil {
		return fmt.Errorf("verify restored trusted input bindings: %w", err)
	}
	if err := archive.Validate(); err != nil {
		return fmt.Errorf("verify restored trusted input root manifest: %w", err)
	}
	return nil
}

func existingTrustedInputRoot(root string, requireEmpty bool) (string, error) {
	if !filepath.IsAbs(root) {
		return "", errors.New("trusted input root must be an absolute path")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve trusted input root: %w", err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", fmt.Errorf("inspect trusted input root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("trusted input root must be an existing real directory")
	}
	if requireEmpty {
		entries, err := os.ReadDir(absolute)
		if err != nil {
			return "", fmt.Errorf("read trusted input destination root: %w", err)
		}
		if len(entries) != 0 {
			return "", errors.New("trusted input destination root must be empty")
		}
	}
	return absolute, nil
}

func inventoryTrustedInputRoot(ctx context.Context, root string, store *PinArchiveStore) ([]bench.TrustedInputInventoryEntry, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("inspect trusted input root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("trusted input root must be a real directory")
	}
	state := trustedInputInventoryState{store: store}
	if err := walkTrustedInputDirectory(ctx, root, "", info, &state); err != nil {
		return nil, err
	}
	sort.Slice(state.entries, func(left, right int) bool {
		return state.entries[left].Locator < state.entries[right].Locator
	})
	return state.entries, nil
}

type trustedInputInventoryState struct {
	entries []bench.TrustedInputInventoryEntry
	bytes   int64
	store   *PinArchiveStore
}

func walkTrustedInputDirectory(ctx context.Context, directory, relative string, expected os.FileInfo, state *trustedInputInventoryState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if expected.Mode()&os.ModeSymlink != 0 || !expected.IsDir() {
		return fmt.Errorf("trusted input directory %q is not a real directory", slashLocator(relative))
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read trusted input directory %q: %w", slashLocator(relative), err)
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		locator := entry.Name()
		if relative != "" {
			locator = relative + "/" + entry.Name()
		}
		if trustedInputDepth(locator) > bench.MaxTrustedInputArchiveDepth {
			return fmt.Errorf("trusted input locator %q exceeds maximum depth %d", locator, bench.MaxTrustedInputArchiveDepth)
		}
		memberPath := filepath.Join(directory, entry.Name())
		memberInfo, err := os.Lstat(memberPath)
		if err != nil {
			return fmt.Errorf("inspect trusted input member %q: %w", locator, err)
		}
		if memberInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("trusted input contains symlink %q", locator)
		}
		switch {
		case memberInfo.IsDir():
			if err := state.add(bench.TrustedInputInventoryEntry{
				Locator: locator,
				Kind:    bench.TrustedInputInventoryDirectory,
				Mode:    uint32(memberInfo.Mode().Perm()),
			}); err != nil {
				return err
			}
			if err := walkTrustedInputDirectory(ctx, memberPath, locator, memberInfo, state); err != nil {
				return err
			}
		case memberInfo.Mode().IsRegular():
			var digest string
			var size int64
			if state.store != nil {
				digest, size, err = state.store.StoreFileContext(ctx, memberPath)
			} else {
				digest, size, err = digestTrustedInputFileContext(ctx, memberPath)
			}
			if err != nil {
				return fmt.Errorf("archive trusted input file %q: %w", locator, err)
			}
			if err := state.add(bench.TrustedInputInventoryEntry{
				Locator:      locator,
				Kind:         bench.TrustedInputInventoryFile,
				ObjectDigest: digest,
				Bytes:        size,
				Mode:         uint32(memberInfo.Mode().Perm()),
			}); err != nil {
				return err
			}
		default:
			return fmt.Errorf("trusted input contains special file %q", locator)
		}
	}
	after, err := os.Lstat(directory)
	if err != nil || !sameStableFile(expected, after) {
		return fmt.Errorf("trusted input directory %q changed while collecting", slashLocator(relative))
	}
	return nil
}

func (state *trustedInputInventoryState) add(entry bench.TrustedInputInventoryEntry) error {
	if len(state.entries) >= bench.MaxTrustedInputArchiveEntries {
		return fmt.Errorf("trusted input exceeds %d inventory members", bench.MaxTrustedInputArchiveEntries)
	}
	if entry.Kind == bench.TrustedInputInventoryFile {
		if entry.Bytes < 0 || entry.Bytes > bench.MaxTrustedInputArchiveFileBytes {
			return fmt.Errorf("trusted input file %q exceeds %d bytes", entry.Locator, bench.MaxTrustedInputArchiveFileBytes)
		}
		if entry.Bytes > bench.MaxTrustedInputArchiveBytes-state.bytes {
			return fmt.Errorf("trusted input exceeds %d bytes", bench.MaxTrustedInputArchiveBytes)
		}
		state.bytes += entry.Bytes
	}
	state.entries = append(state.entries, entry)
	return nil
}

func digestTrustedInputFile(filePath string) (string, int64, error) {
	return digestTrustedInputFileContext(context.Background(), filePath)
}

func digestTrustedInputFileContext(ctx context.Context, filePath string) (string, int64, error) {
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	before, err := os.Lstat(filePath)
	if err != nil {
		return "", 0, fmt.Errorf("inspect trusted input file: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return "", 0, errors.New("trusted input path must be a regular non-symlink file")
	}
	if before.Size() < 0 || before.Size() > bench.MaxTrustedInputArchiveFileBytes {
		return "", 0, fmt.Errorf("trusted input file exceeds %d bytes", bench.MaxTrustedInputArchiveFileBytes)
	}
	file, err := os.Open(filePath) // #nosec G304 -- path was reached by a non-symlink root walk
	if err != nil {
		return "", 0, fmt.Errorf("open trusted input file: %w", err)
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return "", 0, fmt.Errorf("inspect opened trusted input file: %w", err)
	}
	if !sameStableFile(before, opened) {
		_ = file.Close()
		return "", 0, errors.New("trusted input file changed while opening")
	}
	hash := sha256.New()
	written, copyErr := copyWithContext(ctx, hash, io.LimitReader(file, bench.MaxTrustedInputArchiveFileBytes+1))
	closeErr := file.Close()
	if copyErr != nil {
		return "", 0, fmt.Errorf("read trusted input file: %w", copyErr)
	}
	if closeErr != nil {
		return "", 0, errors.New("read trusted input file")
	}
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	after, err := os.Lstat(filePath)
	if err != nil || !sameStableFile(before, after) || written != before.Size() {
		return "", 0, errors.New("trusted input file changed while hashing")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), written, nil
}

func verifyTrustedInputBindings(ctx context.Context, root string, bindings []bench.TrustedInputPinBinding) error {
	for _, binding := range bindings {
		if err := ctx.Err(); err != nil {
			return err
		}
		memberPath, err := safeTrustedInputPath(root, binding.Locator)
		if err != nil {
			return err
		}
		var digest string
		switch binding.Kind {
		case bench.TrustedInputPinFile:
			digest, _, err = digestTrustedInputFileContext(ctx, memberPath)
		case bench.TrustedInputPinTree:
			digest, err = hashTrustedInputTree(ctx, memberPath)
		default:
			return fmt.Errorf("trusted input binding %q has unsupported kind %q", binding.Reference, binding.Kind)
		}
		if err != nil {
			return fmt.Errorf("verify trusted input binding %q: %w", binding.Reference, err)
		}
		if digest != binding.PinDigest {
			return fmt.Errorf("trusted input binding %q digest %s does not match pin digest %s", binding.Reference, digest, binding.PinDigest)
		}
	}
	return nil
}

// hashTrustedInputTree uses the same framing as HashTree while observing cancellation.
func hashTrustedInputTree(ctx context.Context, path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("resolve tree path")
	}
	return hashTreeContext(ctx, absolute)
}
func createTrustedInputDirectory(root string, entry bench.TrustedInputInventoryEntry) error {
	path, _, err := safeTrustedInputDestination(root, entry.Locator)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("trusted input destination directory %q already exists", entry.Locator)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect trusted input destination directory %q: %w", entry.Locator, err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return fmt.Errorf("create trusted input destination directory %q: %w", entry.Locator, err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("trusted input destination directory %q was not created safely", entry.Locator)
	}
	return nil
}

func restoreTrustedInputFile(ctx context.Context, root string, entry bench.TrustedInputInventoryEntry, store *PinArchiveStore) error {
	destination, parent, err := safeTrustedInputDestination(root, entry.Locator)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("trusted input destination file %q already exists", entry.Locator)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect trusted input destination file %q: %w", entry.Locator, err)
	}
	temporary, err := os.CreateTemp(parent, ".trusted-input-restore-*")
	if err != nil {
		return fmt.Errorf("create trusted input temporary file %q: %w", entry.Locator, err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	written, err := store.CopyToContext(ctx, entry.ObjectDigest, entry.Bytes, temporary)
	if err != nil {
		return fmt.Errorf("restore trusted input file %q: %w", entry.Locator, err)
	}
	if written != entry.Bytes {
		return fmt.Errorf("restore trusted input file %q wrote %d bytes instead of %d", entry.Locator, written, entry.Bytes)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync trusted input temporary file %q: %w", entry.Locator, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close trusted input temporary file %q: %w", entry.Locator, err)
	}
	if err := os.Link(temporaryPath, destination); err != nil {
		return fmt.Errorf("publish trusted input file %q: %w", entry.Locator, err)
	}
	if err := syncDirectory(parent); err != nil {
		return fmt.Errorf("sync trusted input destination directory %q: %w", entry.Locator, err)
	}
	digest, size, err := digestTrustedInputFileContext(ctx, destination)
	if err != nil {
		return fmt.Errorf("verify restored trusted input file %q: %w", entry.Locator, err)
	}
	if size != entry.Bytes || digest != entry.ObjectDigest {
		return fmt.Errorf("verify restored trusted input file %q", entry.Locator)
	}
	if err := os.Chmod(destination, os.FileMode(entry.Mode)); err != nil {
		return fmt.Errorf("restore trusted input file mode %q: %w", entry.Locator, err)
	}
	info, err := os.Lstat(destination)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || uint32(info.Mode().Perm()) != entry.Mode {
		return fmt.Errorf("verify restored trusted input file mode %q", entry.Locator)
	}
	return nil
}

func setTrustedInputDirectoryMode(root string, entry bench.TrustedInputInventoryEntry) error {
	path, err := safeTrustedInputPath(root, entry.Locator)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("trusted input destination directory %q is not a real directory", entry.Locator)
	}
	if err := os.Chmod(path, os.FileMode(entry.Mode)); err != nil {
		return fmt.Errorf("restore trusted input directory mode %q: %w", entry.Locator, err)
	}
	info, err = os.Lstat(path)
	if err != nil || uint32(info.Mode().Perm()) != entry.Mode {
		return fmt.Errorf("verify restored trusted input directory mode %q", entry.Locator)
	}
	return nil
}

func safeTrustedInputDestination(root, locator string) (string, string, error) {
	destination, err := safeTrustedInputPath(root, locator)
	if err != nil {
		return "", "", err
	}
	parent := filepath.Dir(destination)
	info, err := os.Lstat(parent)
	if err != nil {
		return "", "", fmt.Errorf("inspect trusted input destination parent for %q: %w", locator, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", "", fmt.Errorf("trusted input destination parent for %q is not a real directory", locator)
	}
	return destination, parent, nil
}

func safeTrustedInputPath(root, locator string) (string, error) {
	if locator == "" || strings.HasPrefix(locator, "/") || strings.Contains(locator, "\\") {
		return "", fmt.Errorf("trusted input locator %q is unsafe", locator)
	}
	parts := strings.Split(locator, "/")
	current := root
	rootInfo, err := os.Lstat(current)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return "", errors.New("trusted input root is not a real directory")
	}
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("trusted input locator %q is unsafe", locator)
		}
		current = filepath.Join(current, part)
		if index == len(parts)-1 {
			break
		}
		info, err := os.Lstat(current)
		if err != nil {
			return "", fmt.Errorf("inspect trusted input parent for %q: %w", locator, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("trusted input parent for %q is not a real directory", locator)
		}
	}
	return current, nil
}

func trustedInputDepth(locator string) int {
	return strings.Count(locator, "/") + 1
}

func slashLocator(locator string) string {
	if locator == "" {
		return "."
	}
	return locator
}
