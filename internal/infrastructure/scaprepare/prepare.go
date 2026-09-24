// Package scaprepare materializes public, diagnostic-only SCA benchmark inputs.
// It deliberately never changes the benchmark corpus or its accepted evidence.
package scaprepare

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/safehttp"
	bench "github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

const maxDownloadBytes int64 = 512 << 20

// Config identifies the two output roots. Raw bytes never enter OfflineRoot.
type Config struct {
	OfflineRoot      string
	RawRetentionRoot string
}

// Result records the immutable work completed before mutable database preparation stops.
type Result struct {
	Artifacts []string
	SBOMs     []string
	Pending   []string
}

type provenance struct {
	Reference          string `json:"reference"`
	Origin             string `json:"origin"`
	RawDigest          string `json:"raw_digest"`
	MaterializedDigest string `json:"materialized_digest"`
	Locator            string `json:"locator"`
}

// Prepare creates a diagnostic input tree. It verifies every acquired binary and capability source
// against the catalog binding. Mutable scanner databases are intentionally not synthesized here.
func Prepare(ctx context.Context, catalog bench.Catalog, spec bench.TrustedInputBindingSpec, cfg Config) (Result, error) {
	if err := spec.Validate(catalog); err != nil {
		return Result{}, fmt.Errorf("validate frozen inputs: %w", err)
	}
	if err := validateRoots(cfg); err != nil {
		return Result{}, err
	}
	if err := createFreshRoot(cfg.OfflineRoot); err != nil {
		return Result{}, fmt.Errorf("create offline root: %w", err)
	}
	if err := createFreshRoot(cfg.RawRetentionRoot); err != nil {
		return Result{}, fmt.Errorf("create raw retention root: %w", err)
	}
	pins := make(map[string]bench.ArtifactPin, len(catalog.Pins))
	for _, pin := range catalog.Pins {
		pins[pin.Reference] = pin
	}
	result := Result{}
	provenanceRecords := make([]provenance, 0)
	for _, binding := range spec.Bindings {
		if !strings.HasPrefix(binding.Reference, "binary:") && !strings.HasPrefix(binding.Reference, "capability-source:") {
			continue
		}
		reference := binding.Reference
		pin, ok := pins[reference]
		if !ok || pin.Origin == "" {
			return Result{}, fmt.Errorf("required public origin %q is absent", reference)
		}
		raw, err := fetch(ctx, pin.Origin)
		if err != nil {
			return Result{}, fmt.Errorf("fetch %s: %w", reference, err)
		}
		if err := writeWithin(cfg.RawRetentionRoot, safeName(reference), raw, 0o600); err != nil {
			return Result{}, fmt.Errorf("retain raw %s: %w", reference, err)
		}
		var materialized []byte
		switch {
		case strings.HasPrefix(reference, "binary:"):
			materialized, err = extractBinary(binding.Locator, raw)
		case strings.HasPrefix(reference, "capability-source:"):
			materialized, err = extractCapability(binding.Locator, raw)
		default:
			err = errors.New("unsupported public artifact")
		}
		if err != nil {
			return Result{}, fmt.Errorf("materialize %s: %w", reference, err)
		}
		if digest(materialized) != binding.PinDigest {
			return Result{}, fmt.Errorf("pin mismatch for %s: expected %s, got %s", reference, binding.PinDigest, digest(materialized))
		}
		if err := writeWithin(cfg.OfflineRoot, binding.Locator, materialized, 0o500); err != nil {
			return Result{}, err
		}
		result.Artifacts = append(result.Artifacts, binding.Locator)
		provenanceRecords = append(provenanceRecords, provenance{Reference: reference, Origin: pin.Origin, RawDigest: digest(raw), MaterializedDigest: digest(materialized), Locator: binding.Locator})
	}
	provenanceBody, err := json.MarshalIndent(provenanceRecords, "", "  ")
	if err != nil {
		return Result{}, fmt.Errorf("encode public acquisition provenance: %w", err)
	}
	if err := writeWithin(cfg.RawRetentionRoot, "materialization-provenance.json", append(provenanceBody, '\n'), 0o600); err != nil {
		return Result{}, fmt.Errorf("retain materialization provenance: %w", err)
	}
	// SBOM generation is deferred until the Syft pin is proven above. A generated document that does
	// not match the catalog is rejected, preventing a current image from masquerading as the old target.
	syft := filepath.Join(cfg.OfflineRoot, "tools", "syft")
	for _, target := range catalog.Targets {
		if err := safeDirectory(cfg.OfflineRoot, "sboms"); err != nil {
			return Result{}, fmt.Errorf("prepare SBOM directory: %w", err)
		}
		path := filepath.Join(cfg.OfflineRoot, "sboms", target.ID+".cdx.json")
		if err := generateSBOM(ctx, syft, target.OCIRef, path); err != nil {
			return Result{}, fmt.Errorf("generate SBOM for %s: %w", target.ID, err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return Result{}, fmt.Errorf("read generated SBOM: %w", err)
		}
		if digest(body) != target.SBOMDigest {
			return Result{}, fmt.Errorf("SBOM pin mismatch for %s: expected %s, got %s", target.ID, target.SBOMDigest, digest(body))
		}
		result.SBOMs = append(result.SBOMs, filepath.ToSlash(filepath.Join("sboms", target.ID+".cdx.json")))
	}
	for _, binding := range spec.Bindings {
		if strings.HasPrefix(binding.Reference, "database:") || strings.HasPrefix(binding.Reference, "source:") {
			result.Pending = append(result.Pending, binding.Reference)
		}
	}
	return result, nil
}

// createFreshRoot prevents an operator-provided, pre-populated directory from smuggling a symlink
// into a later materialization path. Roots are intentionally one-shot diagnostic outputs.
func createFreshRoot(root string) error {
	if _, err := os.Lstat(root); err == nil {
		return errors.New("output root must not already exist")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("output root must be a real directory")
	}
	return nil
}

func validateRoots(cfg Config) error {
	for name, value := range map[string]string{"offline root": cfg.OfflineRoot, "raw retention root": cfg.RawRetentionRoot} {
		if !filepath.IsAbs(value) {
			return fmt.Errorf("%s must be absolute", name)
		}
	}
	offline, err := resolvedRoot(cfg.OfflineRoot)
	if err != nil {
		return fmt.Errorf("resolve offline root: %w", err)
	}
	raw, err := resolvedRoot(cfg.RawRetentionRoot)
	if err != nil {
		return fmt.Errorf("resolve raw retention root: %w", err)
	}
	if containsPath(offline, raw) || containsPath(raw, offline) {
		return errors.New("offline and raw retention roots must be disjoint")
	}
	return nil
}

// resolvedRoot resolves every existing parent before comparing roots. A root may not exist yet, but
// a symlink already present in an ancestor must not make two apparently separate paths overlap.
func resolvedRoot(root string) (string, error) {
	clean := filepath.Clean(root)
	var missing []string
	for {
		if _, err := os.Lstat(clean); err == nil {
			resolved, err := filepath.EvalSymlinks(clean)
			if err != nil {
				return "", err
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Clean(resolved), nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(clean)
		if parent == clean {
			return "", errors.New("root has no existing ancestor")
		}
		missing = append(missing, filepath.Base(clean))
		clean = parent
	}
}

func containsPath(parent, candidate string) bool {
	relative, err := filepath.Rel(parent, candidate)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func fetch(ctx context.Context, origin string) ([]byte, error) {
	client := safehttp.New(5*time.Minute, false)
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("public origin exceeded redirect limit")
		}
		if request.URL.Scheme != "https" || request.URL.Host == "" || request.URL.User != nil {
			return errors.New("public origin redirected outside credential-free HTTPS")
		}
		return nil
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("public origin must be credential-free HTTPS")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) == 0 || int64(len(body)) > maxDownloadBytes {
		return nil, errors.New("download size is invalid")
	}
	return body, nil
}

func extractBinary(locator string, raw []byte) ([]byte, error) {
	name := filepath.Base(locator)
	if name == "" || name == "." || name == string(filepath.Separator) {
		return nil, errors.New("binary locator has no filename")
	}
	if !bytes.HasPrefix(raw, []byte{0x1f, 0x8b}) {
		return raw, nil
	}
	return tarMember(raw, name)
}

func extractCapability(locator string, raw []byte) ([]byte, error) {
	var member string
	switch filepath.Base(locator) {
	case "ecosystem.go":
		member = "purl/ecosystem/ecosystem.go"
	case "purl_to_package.go":
		member = "internal/utility/purl/purl_to_package.go"
	default:
		return nil, fmt.Errorf("no public extraction rule for capability locator %q", locator)
	}
	return tarSuffixMember(raw, member)
}

func tarMember(raw []byte, name string) ([]byte, error) {
	return tarFind(raw, func(v string) bool { return v == name || strings.HasSuffix(v, "/"+name) })
}
func tarSuffixMember(raw []byte, suffix string) ([]byte, error) {
	return tarFind(raw, func(v string) bool { return strings.HasSuffix(v, "/"+suffix) })
}
func tarFind(raw []byte, matches func(string) bool) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("open gzip archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && matches(filepath.ToSlash(h.Name)) {
			return io.ReadAll(io.LimitReader(tr, maxDownloadBytes+1))
		}
	}
	return nil, errors.New("required archive member is absent")
}

func generateSBOM(ctx context.Context, syft, reference, output string) error {
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, syft, "packages", "docker:"+reference, "-o", "cyclonedx-json", "--file", output)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "SYFT_CHECK_FOR_APP_UPDATE=false"}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("syft execution: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func writeWithin(root, relative string, body []byte, mode os.FileMode) error {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.Contains(relative, "\\") {
		return errors.New("output relative path is invalid")
	}
	parent := filepath.Dir(relative)
	if parent != "." {
		if err := safeDirectory(root, parent); err != nil {
			return err
		}
	}
	directory := root
	if parent != "." {
		directory = filepath.Join(root, parent)
	}
	tmp, err := os.CreateTemp(directory, ".prepare-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(body); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(root, relative))
}

// safeDirectory creates a root-relative directory while refusing every existing symlink component.
func safeDirectory(root, relative string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("output root must be a real directory")
	}
	for _, component := range strings.Split(filepath.FromSlash(relative), string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return errors.New("output directory component is invalid")
		}
		root = filepath.Join(root, component)
		if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(root)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("output directory %q must be a real directory", component)
		}
	}
	return nil
}
func digest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func safeName(v string) string { return strings.NewReplacer(":", "-", "/", "-", "\\", "-").Replace(v) }
