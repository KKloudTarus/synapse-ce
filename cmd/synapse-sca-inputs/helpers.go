package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"

	capture "github.com/KKloudTarus/synapse-ce/internal/infrastructure/scabench"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func requirePaths(values ...struct {
	name  string
	value string
}) error {
	for _, item := range values {
		if strings.TrimSpace(item.value) == "" {
			return fmt.Errorf("%s is required", item.name)
		}
	}
	return nil
}

func decodeJSONFile(path string, output any) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, bench.MaxJSONBytes+1))
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(raw)) > bench.MaxJSONBytes {
		return fmt.Errorf("decode %s: JSON input exceeds %d byte limit", path, bench.MaxJSONBytes)
	}
	if !utf8.Valid(raw) {
		return fmt.Errorf("decode %s: JSON input is not valid UTF-8", path)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	shapeDecoder := json.NewDecoder(bytes.NewReader(raw))
	shapeDecoder.UseNumber()
	var value any
	if err := shapeDecoder.Decode(&value); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	if err := validateInputJSONShape(value, reflect.TypeOf(output)); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode %s: trailing JSON value", path)
		}
		return fmt.Errorf("decode %s trailing data: %w", path, err)
	}
	return nil
}

const maxInputJSONDepth = 256

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeInputJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("JSON input must contain exactly one top-level value")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}

func consumeInputJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxInputJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxInputJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("invalid JSON object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("invalid JSON object key")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeInputJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeInputJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("invalid JSON array")
		}
	default:
		return fmt.Errorf("invalid JSON delimiter %q", delimiter)
	}
	return nil
}

func validateInputJSONShape(value any, expected reflect.Type) error {
	if expected == nil || expected.Kind() != reflect.Pointer {
		return fmt.Errorf("JSON destination must be a non-nil pointer")
	}
	return validateInputJSONValue(value, expected.Elem())
}

func validateInputJSONValue(value any, expected reflect.Type) error {
	for expected.Kind() == reflect.Pointer {
		expected = expected.Elem()
	}
	switch expected.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		fields := inputJSONFields(expected)
		for key, nested := range object {
			field, exists := fields[key]
			if !exists {
				return fmt.Errorf("unknown JSON field %q", key)
			}
			if err := validateInputJSONValue(nested, field); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		values, ok := value.([]any)
		if !ok {
			return nil
		}
		for _, nested := range values {
			if err := validateInputJSONValue(nested, expected.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		for _, nested := range object {
			if err := validateInputJSONValue(nested, expected.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func inputJSONFields(expected reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, expected.NumField())
	for index := 0; index < expected.NumField(); index++ {
		field := expected.Field(index)
		if field.PkgPath != "" {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
}

func decodeCatalog(path string) (bench.Catalog, error) {
	file, err := os.Open(path)
	if err != nil {
		return bench.Catalog{}, err
	}
	defer file.Close()
	return bench.DecodeCatalog(file)
}

func decodeOracle(path string) (bench.Oracle, error) {
	file, err := os.Open(path)
	if err != nil {
		return bench.Oracle{}, err
	}
	defer file.Close()
	return bench.DecodeOracle(file)
}

func decodeRatchet(path string) (bench.Ratchet, error) {
	file, err := os.Open(path)
	if err != nil {
		return bench.Ratchet{}, err
	}
	defer file.Close()
	return bench.DecodeRatchet(file)
}

func decodeResult(path string) (bench.Result, error) {
	file, err := os.Open(path)
	if err != nil {
		return bench.Result{}, err
	}
	defer file.Close()
	return bench.DecodeResult(file)
}

func decodeSourceFreeze(path string) (bench.SourceFreeze, error) {
	file, err := os.Open(path)
	if err != nil {
		return bench.SourceFreeze{}, err
	}
	defer file.Close()
	return bench.DecodeSourceFreeze(file)
}

func decodeCandidate(path string) (bench.OracleCandidate, error) {
	file, err := os.Open(path)
	if err != nil {
		return bench.OracleCandidate{}, err
	}
	defer file.Close()
	return bench.DecodeOracleCandidate(file)
}

func decodeCrossCheck(path string) (bench.AutomatedCrossCheck, error) {
	file, err := os.Open(path)
	if err != nil {
		return bench.AutomatedCrossCheck{}, err
	}
	defer file.Close()
	return bench.DecodeAutomatedCrossCheck(file)
}

func decodeAdjudication(path string) (bench.AdjudicationRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return bench.AdjudicationRecord{}, err
	}
	defer file.Close()
	return bench.DecodeAdjudicationRecord(file)
}

func decodeReview(path string) (bench.AccountableReview, error) {
	file, err := os.Open(path)
	if err != nil {
		return bench.AccountableReview{}, err
	}
	defer file.Close()
	return bench.DecodeAccountableReview(file)
}

func decodeFinalOracleFreeze(path string) (bench.FinalOracleFreeze, error) {
	file, err := os.Open(path)
	if err != nil {
		return bench.FinalOracleFreeze{}, err
	}
	defer file.Close()
	return bench.DecodeFinalOracleFreeze(file)
}

func decodePlan(path string) (bench.CyclePlan, error) {
	file, err := os.Open(path)
	if err != nil {
		return bench.CyclePlan{}, err
	}
	defer file.Close()
	return bench.DecodeCyclePlan(file)
}

func decodeLedger(path string) (bench.CycleLedger, error) {
	file, err := os.Open(path)
	if err != nil {
		return bench.CycleLedger{}, err
	}
	defer file.Close()
	return bench.DecodeCycleLedger(file)
}

func decodePublicationManifest(path string) (bench.PublicationManifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return bench.PublicationManifest{}, err
	}
	defer file.Close()
	return bench.DecodePublicationManifest(file)
}

func decodeCaptureManifest(path string) (capture.CaptureManifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return capture.CaptureManifest{}, err
	}
	defer file.Close()
	return capture.DecodeCaptureManifest(file)
}

func writeJSONSet(values map[string]any) error {
	if len(values) == 0 {
		return fmt.Errorf("no output records supplied")
	}
	paths := make([]string, 0, len(values))
	encoded := make(map[string][]byte, len(values))
	for path, value := range values {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("output path is required")
		}
		body, err := bench.CanonicalJSON(value)
		if err != nil {
			return fmt.Errorf("encode %s: %w", path, err)
		}
		if int64(len(body)+1) > bench.MaxJSONBytes {
			return fmt.Errorf("output %s exceeds the JSON size limit", path)
		}
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("output %s already exists", path)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("inspect output %s: %w", path, err)
		}
		paths = append(paths, path)
		encoded[path] = append(body, '\n')
	}
	sort.Strings(paths)
	temporary := make(map[string]string, len(paths))
	cleanup := func() {
		for _, path := range temporary {
			_ = os.Remove(path)
		}
	}
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			cleanup()
			return fmt.Errorf("create output directory: %w", err)
		}
		file, err := os.CreateTemp(filepath.Dir(path), ".sca-inputs-*.tmp")
		if err != nil {
			cleanup()
			return fmt.Errorf("create temporary output: %w", err)
		}
		temporary[path] = file.Name()
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			cleanup()
			return err
		}
		if _, err := file.Write(encoded[path]); err != nil {
			_ = file.Close()
			cleanup()
			return fmt.Errorf("write temporary output: %w", err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			cleanup()
			return fmt.Errorf("sync temporary output: %w", err)
		}
		if err := file.Close(); err != nil {
			cleanup()
			return fmt.Errorf("close temporary output: %w", err)
		}
	}
	committed := make([]string, 0, len(paths))
	for _, path := range paths {
		if err := os.Rename(temporary[path], path); err != nil {
			for _, committedPath := range committed {
				_ = os.Remove(committedPath)
			}
			cleanup()
			return fmt.Errorf("commit output %s: %w", path, err)
		}
		delete(temporary, path)
		committed = append(committed, path)
	}
	return nil
}

func resolveRepositoryAsset(root, locator string) (string, error) {
	if strings.TrimSpace(root) == "" || strings.TrimSpace(locator) == "" || filepath.IsAbs(filepath.FromSlash(locator)) {
		return "", fmt.Errorf("repository root and relative locator are required")
	}
	cleanLocator := filepath.Clean(filepath.FromSlash(locator))
	if cleanLocator == "." || cleanLocator == ".." || strings.HasPrefix(cleanLocator, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("repository locator %q escapes the root", locator)
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(absoluteRoot)
	if err != nil {
		return "", fmt.Errorf("resolve repository root: %w", err)
	}
	candidate := filepath.Join(resolvedRoot, cleanLocator)
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve repository asset %q: %w", locator, err)
	}
	relative, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("repository asset %q resolves outside the root", locator)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("repository asset %q is not a regular file", locator)
	}
	return resolved, nil
}

func contentReference(path, locator string) (bench.ContentReference, error) {
	file, err := os.Open(path)
	if err != nil {
		return bench.ContentReference{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return bench.ContentReference{}, err
	}
	if !info.Mode().IsRegular() {
		return bench.ContentReference{}, fmt.Errorf("content reference %q is not a regular file", locator)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, bufio.NewReader(file)); err != nil {
		return bench.ContentReference{}, err
	}
	reference := bench.ContentReference{Locator: filepath.ToSlash(locator), Digest: "sha256:" + hex.EncodeToString(hash.Sum(nil)), Size: info.Size()}
	if err := reference.Validate(); err != nil {
		return bench.ContentReference{}, err
	}
	return reference, nil
}

func contentReferenceForBytes(body []byte, locator string) bench.ContentReference {
	sum := sha256.Sum256(body)
	return bench.ContentReference{Locator: filepath.ToSlash(locator), Digest: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(body))}
}

func catalogPin(catalog bench.Catalog, reference string) (string, error) {
	for _, pin := range catalog.Pins {
		if pin.Reference == reference {
			return pin.Digest, nil
		}
	}
	return "", fmt.Errorf("catalog omits pin %q", reference)
}

func targetByID(catalog bench.Catalog, targetID string) (bench.Target, bool) {
	for _, target := range catalog.Targets {
		if target.ID == targetID {
			return target, true
		}
	}
	return bench.Target{}, false
}

func fileList(root, relativeRoot string, accept func(string) bool) ([]bench.ContentReference, error) {
	base := filepath.Join(root, filepath.FromSlash(relativeRoot))
	info, err := os.Stat(base)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("candidate path %q is not a directory", relativeRoot)
	}
	var references []bench.ContentReference
	err = filepath.WalkDir(base, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == base {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("candidate path contains a symlink: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("candidate path contains a non-regular file: %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		locator := filepath.ToSlash(relative)
		if accept != nil && !accept(locator) {
			return nil
		}
		reference, err := contentReference(path, locator)
		if err != nil {
			return err
		}
		references = append(references, reference)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(references, func(left, right int) bool { return references[left].Locator < references[right].Locator })
	return references, nil
}
