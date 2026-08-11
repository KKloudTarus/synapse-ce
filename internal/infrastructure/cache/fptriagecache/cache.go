// Package fptriagecache provides a bounded, filesystem-backed cache for typed AI false-positive
// triage claims. Entries contain no source text, credentials, gate authority, or evidence references.
// The use case rebinds every hit to the current finding, reapplies deterministic policy, and seals it
// into the current scan's evidence link.
package fptriagecache

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
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	formatVersion  = 1
	maxEntryBytes  = 64 << 10
	maxCacheFiles  = 4096
	staleTempAfter = time.Hour
)

// Cache stores one immutable JSON envelope per content-addressed key. The root must be operator-owned;
// New creates only the AI-triage subdirectory, with owner-only permissions, on the first write.
type Cache struct{ root string }

var _ ports.FPTriageCache = (*Cache)(nil)

func New(root string) *Cache { return &Cache{root: strings.TrimSpace(root)} }

type envelope struct {
	Version       int                          `json:"version"`
	Key           ports.FPTriageCacheKey       `json:"key"`
	Decision      ports.FPTriageCachedDecision `json:"decision"`
	PayloadSHA256 string                       `json:"payload_sha256"`
}

// Load returns a clean miss for absent, corrupt, mismatched, oversized, or obsolete entries. Cache
// integrity is never allowed to turn into scan failure or into an unvalidated model claim.
func (c *Cache) Load(ctx context.Context, key ports.FPTriageCacheKey) (ports.FPTriageCachedDecision, bool, error) {
	if err := ctx.Err(); err != nil || c == nil || c.root == "" || !validKey(key) || !trustedRoot(c.root) {
		return ports.FPTriageCachedDecision{}, false, nil
	}
	path := filepath.Join(c.root, digestKey(key)+".json")
	f, err := os.Open(path)
	if err != nil {
		return ports.FPTriageCachedDecision{}, false, nil
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxEntryBytes+1))
	if err != nil || len(data) > maxEntryBytes {
		return ports.FPTriageCachedDecision{}, false, nil
	}
	var stored envelope
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return ports.FPTriageCachedDecision{}, false, nil
	}
	if err := ensureJSONEOF(decoder); err != nil || stored.Version != formatVersion || stored.Key != key ||
		!validDecision(key, stored.Decision) || stored.PayloadSHA256 != digestPayload(stored.Key, stored.Decision) {
		return ports.FPTriageCachedDecision{}, false, nil
	}
	return stored.Decision, true, nil
}

// Store atomically publishes a validated entry. A valid exact-key entry is retained; corrupt or obsolete
// formats are replaced. Concurrent valid writers may race, but readers never observe a partial file.
func (c *Cache) Store(ctx context.Context, key ports.FPTriageCacheKey, decision ports.FPTriageCachedDecision) error {
	if c == nil || c.root == "" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validKey(key) || !validDecision(key, decision) {
		return fmt.Errorf("AI triage cache: invalid key or decision")
	}
	if err := os.MkdirAll(c.root, 0o700); err != nil {
		return fmt.Errorf("AI triage cache: mkdir: %w", err)
	}
	if err := os.Chmod(c.root, 0o700); err != nil {
		return fmt.Errorf("AI triage cache: secure directory: %w", err)
	}
	data, err := json.Marshal(envelope{
		Version: formatVersion, Key: key, Decision: decision, PayloadSHA256: digestPayload(key, decision),
	})
	if err != nil {
		return fmt.Errorf("AI triage cache: marshal: %w", err)
	}
	dst := filepath.Join(c.root, digestKey(key)+".json")
	if _, err := os.Stat(dst); err == nil {
		if _, ok, _ := c.Load(ctx, key); ok {
			return nil
		}
		// Load proved this exact path unusable. Removing only the fully resolved content-addressed
		// entry lets format upgrades and corruption heal on the next successful model call.
		if err := os.Remove(dst); err != nil {
			return fmt.Errorf("AI triage cache: remove invalid entry: %w", err)
		}
	}
	tmp, err := os.CreateTemp(c.root, ".ai-triage-*.tmp")
	if err != nil {
		return fmt.Errorf("AI triage cache: temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("AI triage cache: chmod: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("AI triage cache: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("AI triage cache: close: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		if _, statErr := os.Stat(dst); statErr == nil {
			return nil // a concurrent writer published the immutable key first
		}
		return fmt.Errorf("AI triage cache: publish: %w", err)
	}
	c.prune()
	return nil
}

func digestKey(key ports.FPTriageCacheKey) string {
	data, _ := json.Marshal(key) // a fixed struct of strings cannot fail to marshal
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func digestPayload(key ports.FPTriageCacheKey, decision ports.FPTriageCachedDecision) string {
	payload := struct {
		Key      ports.FPTriageCacheKey       `json:"key"`
		Decision ports.FPTriageCachedDecision `json:"decision"`
	}{Key: key, Decision: decision}
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func trustedRoot(root string) bool {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	// Windows does not expose Unix ownership bits consistently. The directory is still created and
	// files are written with the strictest portable modes; ACL ownership remains an operator concern.
	return runtime.GOOS == "windows" || info.Mode().Perm()&0o022 == 0
}

func validKey(key ports.FPTriageCacheKey) bool {
	return !key.TenantID.IsZero() && !key.ScopeID.IsZero() && strings.TrimSpace(key.FindingFingerprint) != "" &&
		validSHA256(key.SourceSHA256) && validSHA256(key.ContextSHA256) &&
		strings.TrimSpace(key.ProposerProvider) != "" && strings.TrimSpace(key.ProposerModel) != "" &&
		(strings.TrimSpace(key.VerifierModel) == "") == (strings.TrimSpace(key.VerifierProvider) == "") &&
		strings.TrimSpace(key.PromptVersion) != "" && strings.TrimSpace(key.PolicyVersion) != ""
}

func validDecision(key ports.FPTriageCacheKey, decision ports.FPTriageCachedDecision) bool {
	claim := judgment.CritiqueClaim{
		Verdict: judgment.CritiqueVerdict(decision.Verdict), Driver: decision.Driver, Confidence: decision.Confidence,
	}
	if claim.Validate() != nil || (key.VerifierModel == "") != !decision.VerifierPresent {
		return false
	}
	if !decision.VerifierPresent {
		return decision.VerifierVerdict == "" && decision.VerifierDriver == "" && decision.VerifierConfidence == 0
	}
	verifier := judgment.CritiqueClaim{
		Verdict: judgment.CritiqueVerdict(decision.VerifierVerdict),
		Driver:  decision.VerifierDriver, Confidence: decision.VerifierConfidence,
	}
	return verifier.Validate() == nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("unexpected trailing JSON")
	}
	return err
}

func (c *Cache) prune() {
	entries, err := os.ReadDir(c.root)
	if err != nil {
		return
	}
	type candidate struct {
		name    string
		modTime time.Time
	}
	now := time.Now()
	files := make([]candidate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		switch {
		case strings.HasSuffix(entry.Name(), ".tmp") && now.Sub(info.ModTime()) > staleTempAfter:
			_ = os.Remove(filepath.Join(c.root, entry.Name()))
		case strings.HasSuffix(entry.Name(), ".json"):
			files = append(files, candidate{name: entry.Name(), modTime: info.ModTime()})
		}
	}
	if len(files) <= maxCacheFiles {
		return
	}
	sort.Slice(files, func(i, j int) bool { return files[i].modTime.Before(files[j].modTime) })
	for _, file := range files[:len(files)-maxCacheFiles] {
		_ = os.Remove(filepath.Join(c.root, file.name))
	}
}
