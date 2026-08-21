// Command synapse-verify-restore verifies a restored PostgreSQL database and
// evidence bucket without changing either system.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/blob"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/postgres"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/restoreverify"
)

const (
	defaultTimeout = 2 * time.Minute
	maxPoolConns   = int32(2)
)

var errIntegrity = errors.New("restore verification found integrity failures")

type settings struct {
	dbDSN         string
	blobEndpoint  string
	blobAccessKey string
	blobSecretKey string
	blobBucket    string
	blobUseSSL    bool
	timeout       time.Duration
	expectedState *ports.RestoreExpectedState
}

type verifier interface {
	Verify(context.Context) (restoreverify.Result, error)
}

type buildVerifier func(context.Context, settings) (verifier, func(), error)

func main() {
	manifestPath := flag.String("expected-state", "", "path to expected restore state manifest")
	flag.Parse()
	cfg, err := loadSettings(os.Getenv)
	path := strings.TrimSpace(*manifestPath)
	if path == "" {
		path = strings.TrimSpace(os.Getenv("SYNAPSE_RESTORE_VERIFY_EXPECTED_STATE"))
	}
	if err == nil && path != "" {
		cfg.expectedState, err = loadExpectedState(path)
	}
	if err != nil {
		writeError(err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, cfg, newVerifier, os.Stdout); err != nil {
		writeError(err)
		os.Exit(1)
	}
}

func loadSettings(getenv func(string) string) (settings, error) {
	cfg := settings{
		dbDSN:         strings.TrimSpace(getenv("SYNAPSE_DB_DSN")),
		blobEndpoint:  strings.TrimSpace(getenv("SYNAPSE_BLOB_ENDPOINT")),
		blobAccessKey: strings.TrimSpace(getenv("SYNAPSE_BLOB_ACCESS_KEY")),
		blobSecretKey: strings.TrimSpace(getenv("SYNAPSE_BLOB_SECRET_KEY")),
		blobBucket:    strings.TrimSpace(getenv("SYNAPSE_BLOB_BUCKET")),
	}
	if cfg.dbDSN == "" {
		return settings{}, errors.New("SYNAPSE_DB_DSN is required")
	}
	if cfg.blobEndpoint == "" || cfg.blobAccessKey == "" || cfg.blobSecretKey == "" || cfg.blobBucket == "" {
		return settings{}, errors.New("SYNAPSE_BLOB_ENDPOINT, SYNAPSE_BLOB_ACCESS_KEY, SYNAPSE_BLOB_SECRET_KEY, and SYNAPSE_BLOB_BUCKET are required")
	}

	useSSL, err := parseBool(getenv("SYNAPSE_BLOB_USE_SSL"))
	if err != nil {
		return settings{}, errors.New("SYNAPSE_BLOB_USE_SSL must be a boolean")
	}
	cfg.blobUseSSL = useSSL

	cfg.timeout = defaultTimeout
	if raw := strings.TrimSpace(getenv("SYNAPSE_RESTORE_VERIFY_TIMEOUT")); raw != "" {
		cfg.timeout, err = time.ParseDuration(raw)
		if err != nil || cfg.timeout <= 0 {
			return settings{}, errors.New("SYNAPSE_RESTORE_VERIFY_TIMEOUT must be a positive duration")
		}
	}
	return cfg, nil
}

func parseBool(value string) (bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return false, nil
	}
	switch strings.ToLower(value) {
	case "1", "t", "true", "y", "yes", "on":
		return true, nil
	case "0", "f", "false", "n", "no", "off":
		return false, nil
	default:
		return false, errors.New("invalid boolean")
	}
}

func run(parent context.Context, cfg settings, build buildVerifier, stdout io.Writer) error {
	if build == nil {
		return errors.New("initialize restore verification")
	}
	if cfg.timeout <= 0 {
		cfg.timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(parent, cfg.timeout)
	defer cancel()

	svc, cleanup, err := build(ctx, cfg)
	if err != nil {
		return errors.New("initialize restore verification")
	}
	if cleanup != nil {
		defer cleanup()
	}
	if svc == nil {
		return errors.New("initialize restore verification")
	}

	result, err := svc.Verify(ctx)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("restore verification timed out")
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return errors.New("restore verification canceled")
		}
		return errors.New("restore verification failed")
	}
	if err := writeJSON(stdout, result); err != nil {
		return err
	}
	if !result.Intact {
		return errIntegrity
	}
	return nil
}

func newVerifier(ctx context.Context, cfg settings) (verifier, func(), error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.dbDSN)
	if err != nil {
		return nil, nil, errors.New("parse PostgreSQL configuration")
	}
	poolCfg.MaxConns = maxPoolConns
	poolCfg.MinConns = 0
	poolCfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, nil, errors.New("connect PostgreSQL")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, nil, errors.New("connect PostgreSQL")
	}

	blobs, err := blob.NewReadOnlyMinIO(ctx, blob.Config{
		Endpoint: cfg.blobEndpoint, AccessKey: cfg.blobAccessKey, SecretKey: cfg.blobSecretKey,
		Bucket: cfg.blobBucket, UseSSL: cfg.blobUseSSL,
	})
	if err != nil {
		pool.Close()
		return nil, nil, errors.New("connect evidence blob store")
	}

	// The restore reader fails closed unless the database identity may read every
	// tenant's chain, so a normal least-privilege runtime role cannot verify a restore.
	evidenceStore, err := postgres.NewReadOnlyEvidenceStore(ctx, pool)
	if err != nil {
		pool.Close()
		return nil, nil, errors.New("restore verification requires a recovery database identity")
	}
	auditLog := postgres.NewAuditLog(pool)
	args := []ports.RestoreExpectedState{}
	if cfg.expectedState != nil {
		args = append(args, *cfg.expectedState)
	}
	svc, err := restoreverify.NewService(evidenceStore, blobs, auditLog, auditLog, args...)
	if err != nil {
		pool.Close()
		return nil, nil, errors.New("initialize restore verification")
	}
	return svc, pool.Close, nil
}

func writeJSON(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return fmt.Errorf("write restore verification report: %w", err)
	}
	return nil
}

func writeError(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "synapse-verify-restore: %s\n", err)
}

// loadExpectedState parses an independently captured, content-free expected-state manifest.
func loadExpectedState(path string) (*ports.RestoreExpectedState, error) {
	path = strings.TrimSpace(path)
	if path == "" || filepath.Clean(path) == "." {
		return nil, errors.New("expected state manifest path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read expected state manifest")
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var state ports.RestoreExpectedState
	if err := dec.Decode(&state); err != nil {
		return nil, errors.New("parse expected state manifest")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, errors.New("parse expected state manifest")
	}
	if state.AuditHead != "" && !isSHA256(state.AuditHead) {
		return nil, errors.New("invalid expected state manifest")
	}
	seenChains := map[string]struct{}{}
	for _, chain := range state.EvidenceChains {
		if chain.EngagementID.IsZero() || chain.Count < 0 || (chain.Count == 0 && chain.Head != "") || (chain.Count > 0 && !isSHA256(chain.Head)) {
			return nil, errors.New("invalid expected state manifest")
		}
		if _, ok := seenChains[chain.EngagementID.String()]; ok {
			return nil, errors.New("invalid expected state manifest")
		}
		seenChains[chain.EngagementID.String()] = struct{}{}
	}
	seenVersions := map[int64]struct{}{}
	for _, version := range state.MigrationVersions {
		if version <= 0 {
			return nil, errors.New("invalid expected state manifest")
		}
		if _, ok := seenVersions[version]; ok {
			return nil, errors.New("invalid expected state manifest")
		}
		seenVersions[version] = struct{}{}
	}
	return &state, nil
}

func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
