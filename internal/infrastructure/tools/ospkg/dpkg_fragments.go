package ospkg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Distroless stores installed package control records without a Status field.
// Enumerate once in filename order, bounded by entries and aggregate bytes. Work
// is O(entries log entries + bytes), with at most maxPackages entries and 64 MiB
// of control data; each file is capped at maxDBLine bytes. Root confines reads
// even when an ancestor is a symlink; directory and leaf symlinks are rejected.
func parseDpkgFragments(ctx context.Context, rootfsDir, namespace, tag string, entryLimit, byteLimit int) ([]sbom.Component, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(rootfsDir)
	if err != nil {
		return nil, fmt.Errorf("open dpkg root: %w", err)
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(dpkgStatusDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect dpkg status.d: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("dpkg status.d is not a regular directory")
	}
	dir, err := root.OpenRoot(dpkgStatusDir)
	if err != nil {
		return nil, fmt.Errorf("open dpkg status.d: %w", err)
	}
	defer func() { _ = dir.Close() }()
	f, err := dir.Open(".")
	if err != nil {
		return nil, fmt.Errorf("read dpkg status.d: %w", err)
	}
	entries, readErr := f.ReadDir(entryLimit + 1)
	_ = f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, fmt.Errorf("enumerate dpkg status.d: %w", readErr)
	}
	if len(entries) > entryLimit {
		return nil, fmt.Errorf("dpkg status.d exceeds the %d-entry limit", entryLimit)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var out []sbom.Component
	totalBytes := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if strings.HasSuffix(entry.Name(), ".md5sums") {
			continue
		}
		info, err := dir.Lstat(entry.Name())
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("dpkg status.d entry %q is not a readable regular file", entry.Name())
		}
		file, err := dir.Open(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("open dpkg status.d entry %q: %w", entry.Name(), err)
		}
		limit := min(maxDBLine, byteLimit-totalBytes)
		data, readErr := io.ReadAll(io.LimitReader(file, int64(limit)+1))
		_ = file.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read dpkg status.d entry %q: %w", entry.Name(), readErr)
		}
		if len(data) > limit {
			return nil, fmt.Errorf("dpkg status.d exceeds its file or aggregate byte limit")
		}
		totalBytes += len(data)
		valid, invalid := false, false
		extract := func(fields map[string]string) (string, string, string, string, bool) {
			if cleanField(fields["Package"]) != "" && cleanField(fields["Version"]) != "" {
				valid = true
			} else {
				invalid = true
			}
			if _, exists := fields["Status"]; !exists {
				fields["Status"] = "install ok installed"
			}
			return dpkgExtract(fields)
		}
		location := filepath.Join(rootfsDir, dpkgStatusDir, entry.Name())
		components, err := parseOSDBReader(ctx, bytes.NewReader(data), location, dpkgFieldKeys, extract, "deb", namespace, tag)
		if err != nil {
			return nil, fmt.Errorf("parse dpkg status.d entry %q: %w", entry.Name(), err)
		}
		if !valid || invalid {
			return nil, fmt.Errorf("dpkg status.d entry %q has no package name and version", entry.Name())
		}
		if len(out)+len(components) > maxPackages {
			return nil, fmt.Errorf("dpkg status.d exceeds the %d-package limit", maxPackages)
		}
		out = append(out, components...)
	}
	return out, ctx.Err()
}
