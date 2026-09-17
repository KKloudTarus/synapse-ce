package benchcycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestExecuteTwoPassKeepsCanonicalPairsAfterOutOfOrderCompletion(t *testing.T) {
	plan := TwoPassPlan[string]{
		Cells: []PlanCell[string]{
			{Key: "alpha", Cell: "first"},
			{Key: "beta", Cell: "second"},
		},
		Workers: 2,
	}
	started := make(chan AttemptAddress, 4)
	completed := make(chan AttemptAddress, 4)
	allowAlpha := make(chan struct{})
	allowBeta := make(chan struct{})
	compared := make([]string, 0, 2)
	done := make(chan struct {
		pairs []PairOutcome[string, string]
		err   error
	}, 1)

	go func() {
		pairs, err := ExecuteTwoPass(context.Background(), plan,
			func(ctx context.Context, attempt Attempt[string]) (AttemptOutcome[string], error) {
				started <- attempt.Address
				if attempt.Address.Repetition == 1 {
					if attempt.Address.CellKey == "alpha" {
						select {
						case <-allowAlpha:
						case <-ctx.Done():
							return AttemptOutcome[string]{}, ctx.Err()
						}
					} else {
						select {
						case <-allowBeta:
						case <-ctx.Done():
							return AttemptOutcome[string]{}, ctx.Err()
						}
					}
				}
				completed <- attempt.Address
				return AttemptOutcome[string]{Address: attempt.Address, Outcome: fmt.Sprintf("%d:%s", attempt.Address.Repetition, attempt.Cell)}, nil
			},
			func(_ context.Context, pair PairOutcome[string, string]) error {
				compared = append(compared, pair.Cell.Key)
				return nil
			},
		)
		done <- struct {
			pairs []PairOutcome[string, string]
			err   error
		}{pairs: pairs, err: err}
	}()

	firstPass := receiveAddresses(t, started, 2)
	if !sameAddresses(firstPass, []AttemptAddress{{CellKey: "alpha", Repetition: 1}, {CellKey: "beta", Repetition: 1}}) {
		t.Fatalf("first pass attempts = %#v", firstPass)
	}
	close(allowBeta)
	if completedAttempt := <-completed; completedAttempt != (AttemptAddress{CellKey: "beta", Repetition: 1}) {
		t.Fatalf("first completed attempt = %#v", completedAttempt)
	}
	select {
	case attempt := <-started:
		t.Fatalf("pass two began before pass one completed: %#v", attempt)
	default:
	}
	close(allowAlpha)

	result := <-done
	if result.err != nil {
		t.Fatalf("execute two pass: %v", result.err)
	}
	want := []PairOutcome[string, string]{
		{
			Cell: PlanCell[string]{Key: "alpha", Cell: "first"},
			Outcomes: [2]AttemptOutcome[string]{
				{Address: AttemptAddress{CellKey: "alpha", Repetition: 1}, Outcome: "1:first"},
				{Address: AttemptAddress{CellKey: "alpha", Repetition: 2}, Outcome: "2:first"},
			},
		},
		{
			Cell: PlanCell[string]{Key: "beta", Cell: "second"},
			Outcomes: [2]AttemptOutcome[string]{
				{Address: AttemptAddress{CellKey: "beta", Repetition: 1}, Outcome: "1:second"},
				{Address: AttemptAddress{CellKey: "beta", Repetition: 2}, Outcome: "2:second"},
			},
		},
	}
	if !reflect.DeepEqual(result.pairs, want) {
		t.Fatalf("pairs = %#v, want %#v", result.pairs, want)
	}
	if wantCompared := []string{"alpha", "beta"}; !reflect.DeepEqual(compared, wantCompared) {
		t.Fatalf("comparison order = %#v, want %#v", compared, wantCompared)
	}
}

func TestExecuteTwoPassRejectsUnsafeAndUnboundedPlans(t *testing.T) {
	for _, test := range []struct {
		name string
		plan TwoPassPlan[string]
	}{
		{name: "empty", plan: TwoPassPlan[string]{}},
		{name: "empty cell key", plan: TwoPassPlan[string]{Cells: []PlanCell[string]{{Key: ""}}}},
		{name: "duplicate key", plan: TwoPassPlan[string]{Cells: []PlanCell[string]{{Key: "same"}, {Key: "same"}}}},
		{name: "ASCII control key", plan: TwoPassPlan[string]{Cells: []PlanCell[string]{{Key: "\x00"}}}},
		{name: "Unicode control key", plan: TwoPassPlan[string]{Cells: []PlanCell[string]{{Key: "cell"}}}},
		{name: "leading Unicode whitespace", plan: TwoPassPlan[string]{Cells: []PlanCell[string]{{Key: " cell"}}}},
		{name: "trailing Unicode whitespace", plan: TwoPassPlan[string]{Cells: []PlanCell[string]{{Key: "cell "}}}},
		{name: "too many cells", plan: TwoPassPlan[string]{Cells: make([]PlanCell[string], MaxTwoPassCells+1)}},
		{name: "too many workers", plan: TwoPassPlan[string]{Cells: []PlanCell[string]{{Key: "cell"}}, Workers: MaxTwoPassWorkers + 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ExecuteTwoPass(context.Background(), test.plan,
				func(_ context.Context, attempt Attempt[string]) (AttemptOutcome[string], error) {
					t.Fatalf("captured invalid plan attempt %#v", attempt)
					return AttemptOutcome[string]{}, nil
				},
				nil,
			)
			if err == nil {
				t.Fatal("accepted invalid plan")
			}
		})
	}
}

func TestExecuteTwoPassSupportsTenThousandCells(t *testing.T) {
	cells := make([]PlanCell[struct{}], MaxTwoPassCells)
	for index := range cells {
		cells[index].Key = fmt.Sprintf("reachability:cell:%d", index)
	}
	pairs, err := ExecuteTwoPass(context.Background(), TwoPassPlan[struct{}]{Cells: cells},
		func(_ context.Context, attempt Attempt[struct{}]) (AttemptOutcome[struct{}], error) {
			return AttemptOutcome[struct{}]{Address: attempt.Address}, nil
		},
		nil,
	)
	if err != nil {
		t.Fatalf("execute maximum plan: %v", err)
	}
	if len(pairs) != MaxTwoPassCells {
		t.Fatalf("pairs = %d, want %d", len(pairs), MaxTwoPassCells)
	}
}

func TestExecuteTwoPassAcceptsOpaqueStableCellKeys(t *testing.T) {
	key := "route:GET /repos/{owner}/{repository}"
	pairs, err := ExecuteTwoPass(context.Background(), TwoPassPlan[string]{Cells: []PlanCell[string]{{Key: key, Cell: "value"}}},
		func(_ context.Context, attempt Attempt[string]) (AttemptOutcome[string], error) {
			return AttemptOutcome[string]{Address: attempt.Address, Outcome: attempt.Cell}, nil
		},
		nil,
	)
	if err != nil {
		t.Fatalf("execute opaque key: %v", err)
	}
	if len(pairs) != 1 || pairs[0].Cell.Key != key {
		t.Fatalf("pairs = %#v", pairs)
	}
}

func TestExecuteTwoPassRejectsDuplicateAndMissingAttemptOutcome(t *testing.T) {
	pairs, err := ExecuteTwoPass(context.Background(), TwoPassPlan[string]{Cells: []PlanCell[string]{{Key: "alpha", Cell: "first"}, {Key: "beta", Cell: "second"}}},
		func(_ context.Context, _ Attempt[string]) (AttemptOutcome[string], error) {
			return AttemptOutcome[string]{
				Address: AttemptAddress{CellKey: "alpha", Repetition: 1},
				Outcome: "duplicate attempt",
			}, nil
		},
		nil,
	)
	if err == nil {
		t.Fatal("accepted a duplicate attempt outcome")
	}
	if pairs != nil {
		t.Fatalf("partial pairs = %#v", pairs)
	}
}

func TestExecuteTwoPassCancelsAndJoinsWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan AttemptAddress, 2)
	stopped := make(chan AttemptAddress, 2)
	done := make(chan struct {
		pairs []PairOutcome[string, string]
		err   error
	}, 1)
	plan := TwoPassPlan[string]{
		Cells:   []PlanCell[string]{{Key: "alpha", Cell: "first"}, {Key: "beta", Cell: "second"}},
		Workers: 2,
	}
	go func() {
		pairs, err := ExecuteTwoPass(ctx, plan,
			func(ctx context.Context, attempt Attempt[string]) (AttemptOutcome[string], error) {
				entered <- attempt.Address
				<-ctx.Done()
				stopped <- attempt.Address
				return AttemptOutcome[string]{}, ctx.Err()
			},
			nil,
		)
		done <- struct {
			pairs []PairOutcome[string, string]
			err   error
		}{pairs: pairs, err: err}
	}()

	_ = receiveAddresses(t, entered, 2)
	cancel()
	result := <-done
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", result.err)
	}
	if result.pairs != nil {
		t.Fatalf("partial pairs = %#v", result.pairs)
	}
	if stoppedAttempts := receiveAddresses(t, stopped, 2); len(stoppedAttempts) != 2 {
		t.Fatalf("stopped attempts = %#v", stoppedAttempts)
	}
}

func TestEvidenceStoreRejectsUnsafeNames(t *testing.T) {
	store, err := NewEvidenceStore(t.TempDir(), EvidenceLimits{MaxArtifactBytes: 8, MaxTotalBytes: 16, MaxFiles: 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		address  AttemptAddress
		artifact string
	}{
		{name: "empty artifact", address: AttemptAddress{CellKey: "cell", Repetition: 1}},
		{name: "traversing artifact", address: AttemptAddress{CellKey: "cell", Repetition: 1}, artifact: "../escape"},
		{name: "nested artifact", address: AttemptAddress{CellKey: "cell", Repetition: 1}, artifact: "nested/file"},
		{name: "unsafe cell", address: AttemptAddress{CellKey: "\x00", Repetition: 1}, artifact: "evidence.json"},
		{name: "invalid repetition", address: AttemptAddress{CellKey: "cell", Repetition: 3}, artifact: "evidence.json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := store.Write(context.Background(), test.address, test.artifact, bytes.NewReader([]byte("data"))); err == nil {
				t.Fatal("accepted unsafe evidence location")
			}
		})
	}
}

func TestEvidenceStoreHashesOpaqueCellKeys(t *testing.T) {
	root := t.TempDir()
	store, err := NewEvidenceStore(root, EvidenceLimits{MaxArtifactBytes: 8, MaxTotalBytes: 8, MaxFiles: 1})
	if err != nil {
		t.Fatal(err)
	}
	key := "../route:GET /items/{id}"
	receipt, err := store.Write(context.Background(), AttemptAddress{CellKey: key, Repetition: 1}, "evidence.json", bytes.NewReader([]byte("data")))
	if err != nil {
		t.Fatalf("write opaque key evidence: %v", err)
	}
	wantReference := "attempts/" + evidenceCellDirectory(key) + "/pass-1/evidence.json"
	if receipt.Reference != wantReference {
		t.Fatalf("receipt reference = %q, want %q", receipt.Reference, wantReference)
	}
	if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(receipt.Reference))); err != nil {
		t.Fatalf("hashed evidence path: %v", err)
	}
}

func TestEvidenceStoreReleasesAggregateAfterFailedWrite(t *testing.T) {
	root := t.TempDir()
	store, err := NewEvidenceStore(root, EvidenceLimits{MaxArtifactBytes: 4, MaxTotalBytes: 6, MaxFiles: 2})
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Write(context.Background(), AttemptAddress{CellKey: "alpha", Repetition: 1}, "first.json", bytes.NewReader([]byte("four")))
	if err != nil {
		t.Fatalf("write first evidence: %v", err)
	}
	if want := digest([]byte("four")); first.Digest != want || first.Size != 4 || first.Reference != "attempts/"+evidenceCellDirectory("alpha")+"/pass-1/first.json" {
		t.Fatalf("first receipt = %#v", first)
	}

	failedPath := filepath.Join(root, "attempts", evidenceCellDirectory("alpha"), "pass-2", "second.json")
	if _, err := store.Write(context.Background(), AttemptAddress{CellKey: "alpha", Repetition: 2}, "second.json", bytes.NewReader([]byte("four"))); err == nil {
		t.Fatal("accepted evidence beyond the aggregate limit")
	}
	if _, err := os.Lstat(failedPath); !os.IsNotExist(err) {
		t.Fatalf("failed evidence remained at %q: %v", failedPath, err)
	}
	third, err := store.Write(context.Background(), AttemptAddress{CellKey: "beta", Repetition: 1}, "third.json", bytes.NewReader([]byte("ok")))
	if err != nil {
		t.Fatalf("aggregate reservation was not released: %v", err)
	}
	if third.Size != 2 {
		t.Fatalf("third receipt = %#v", third)
	}
}

func TestEvidenceStoreKeepsAggregateBoundUnderConcurrentWrites(t *testing.T) {
	store, err := NewEvidenceStore(t.TempDir(), EvidenceLimits{MaxArtifactBytes: 4, MaxTotalBytes: 4, MaxFiles: 2})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errorsByAttempt := make(chan error, 2)
	for _, address := range []AttemptAddress{{CellKey: "alpha", Repetition: 1}, {CellKey: "beta", Repetition: 1}} {
		go func(address AttemptAddress) {
			<-start
			_, err := store.Write(context.Background(), address, "evidence.json", bytes.NewReader([]byte("four")))
			errorsByAttempt <- err
		}(address)
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-errorsByAttempt; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful writes = %d, want 1", successes)
	}
}

func TestEvidenceStoreStopsBeforeWritingAfterCancellation(t *testing.T) {
	root := t.TempDir()
	store, err := NewEvidenceStore(root, EvidenceLimits{MaxArtifactBytes: 8, MaxTotalBytes: 8, MaxFiles: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	reader := readerFunc(func(p []byte) (int, error) {
		copy(p, "data")
		cancel()
		return 4, io.EOF
	})
	_, err = store.Write(ctx, AttemptAddress{CellKey: "cell", Repetition: 1}, "evidence.json", reader)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("write error = %v, want context cancellation", err)
	}
	path := filepath.Join(root, "attempts", evidenceCellDirectory("cell"), "pass-1", "evidence.json")
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("cancelled evidence remained at %q: %v", path, err)
	}
}

func TestPublicationWriteEnforcesByteAndFileLimits(t *testing.T) {
	t.Run("per file", func(t *testing.T) {
		publication, err := BeginPublication(filepath.Join(t.TempDir(), "output"), PublicationLimits{MaxFileBytes: 4, MaxTotalBytes: 8, MaxFiles: 2},
			func(context.Context) error { return nil },
			func(context.Context, string, []FileIdentity) error { return nil },
		)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = publication.Abort() }()
		if _, err := publication.Write(context.Background(), "large.json", bytes.NewReader([]byte("fives"))); err == nil {
			t.Fatal("accepted an oversized publication file")
		}
		if _, err := os.Lstat(filepath.Join(publication.stage, "large.json")); !os.IsNotExist(err) {
			t.Fatalf("oversized file remained in stage: %v", err)
		}
	})
	t.Run("aggregate", func(t *testing.T) {
		publication, err := BeginPublication(filepath.Join(t.TempDir(), "output"), PublicationLimits{MaxFileBytes: 4, MaxTotalBytes: 6, MaxFiles: 2},
			func(context.Context) error { return nil },
			func(context.Context, string, []FileIdentity) error { return nil },
		)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = publication.Abort() }()
		if _, err := publication.Write(context.Background(), "first.json", bytes.NewReader([]byte("four"))); err != nil {
			t.Fatal(err)
		}
		if _, err := publication.Write(context.Background(), "second.json", bytes.NewReader([]byte("three"))); err == nil {
			t.Fatal("accepted publication files beyond aggregate byte limit")
		}
	})
	t.Run("file count", func(t *testing.T) {
		publication, err := BeginPublication(filepath.Join(t.TempDir(), "output"), PublicationLimits{MaxFileBytes: 4, MaxTotalBytes: 8, MaxFiles: 1},
			func(context.Context) error { return nil },
			func(context.Context, string, []FileIdentity) error { return nil },
		)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = publication.Abort() }()
		if _, err := publication.Write(context.Background(), "first.json", bytes.NewReader([]byte("one"))); err != nil {
			t.Fatal(err)
		}
		if _, err := publication.Write(context.Background(), "second.json", bytes.NewReader([]byte("two"))); err == nil {
			t.Fatal("accepted publication files beyond file limit")
		}
	})
}

func TestPublicationConfiguresCleanupTimeout(t *testing.T) {
	for _, test := range []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{name: "default", want: DefaultPublicationCleanupTimeout},
		{name: "override", timeout: 2 * time.Minute, want: 2 * time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			limits := testPublicationLimits()
			limits.CleanupTimeout = test.timeout
			publication, err := BeginPublication(filepath.Join(t.TempDir(), "output"), limits,
				func(context.Context) error { return nil },
				func(context.Context, string, []FileIdentity) error { return nil },
			)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = publication.Abort() }()
			if publication.cleanupTimeout != test.want {
				t.Fatalf("cleanup timeout = %s, want %s", publication.cleanupTimeout, test.want)
			}
		})
	}
	for _, timeout := range []time.Duration{-time.Second, MaxPublicationCleanupTimeout + time.Nanosecond} {
		limits := testPublicationLimits()
		limits.CleanupTimeout = timeout
		if _, err := BeginPublication(filepath.Join(t.TempDir(), "output"), limits,
			func(context.Context) error { return nil },
			func(context.Context, string, []FileIdentity) error { return nil },
		); err == nil {
			t.Fatalf("accepted cleanup timeout %s", timeout)
		}
	}
}

func TestPublicationFailedNestedWriteCannotPublishLeftoverDirectory(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output")
	publication, err := BeginPublication(output, PublicationLimits{MaxFileBytes: 4, MaxTotalBytes: 8, MaxFiles: 2},
		func(context.Context) error { return nil },
		func(context.Context, string, []FileIdentity) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publication.Write(context.Background(), "nested/large.json", bytes.NewReader([]byte("fives"))); err == nil {
		t.Fatal("accepted an oversized nested publication file")
	}
	if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("ok")); err != nil {
		t.Fatal(err)
	}
	stage := publication.stage
	if err := publication.Commit(context.Background()); err == nil {
		t.Fatal("published a leftover directory from a failed nested write")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("destination exists after leftover directory rejection: %v", err)
	}
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("stage remains after leftover directory rejection: %v", err)
	}
}

func TestPublicationCommitRejectsEmptyAndOversizedStages(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		cleaned := false
		publication, err := BeginPublication(filepath.Join(t.TempDir(), "output"), testPublicationLimits(),
			func(context.Context) error {
				cleaned = true
				return nil
			},
			func(context.Context, string, []FileIdentity) error { return nil },
		)
		if err != nil {
			t.Fatal(err)
		}
		stage := publication.stage
		if err := publication.Commit(context.Background()); err == nil {
			t.Fatal("published an empty stage")
		}
		if !cleaned {
			t.Fatal("empty-stage failure skipped cleanup")
		}
		if _, err := os.Lstat(stage); !os.IsNotExist(err) {
			t.Fatalf("empty stage remained after failed commit: %v", err)
		}
	})
	t.Run("mutated oversized", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "output")
		cleaned := false
		publication, err := BeginPublication(output, PublicationLimits{MaxFileBytes: 4, MaxTotalBytes: 8, MaxFiles: 1},
			func(context.Context) error {
				cleaned = true
				return nil
			},
			func(context.Context, string, []FileIdentity) error { return nil },
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("ok")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(publication.stage, "result.json"), bytes.Repeat([]byte("x"), 5), 0o600); err != nil {
			t.Fatal(err)
		}
		stage := publication.stage
		if err := publication.Commit(context.Background()); err == nil {
			t.Fatal("published an oversized mutated stage")
		}
		if !cleaned {
			t.Fatal("oversized-stage failure skipped cleanup")
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("destination exists after oversized stage rejection: %v", err)
		}
		if _, err := os.Lstat(stage); !os.IsNotExist(err) {
			t.Fatalf("oversized stage remained after failed commit: %v", err)
		}
	})
}

func TestPublicationCommitReappliesLimitsToMutatedStage(t *testing.T) {
	t.Run("aggregate bytes", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "output")
		publication, err := BeginPublication(output, PublicationLimits{MaxFileBytes: 4, MaxTotalBytes: 6, MaxFiles: 2},
			func(context.Context) error { return nil },
			func(context.Context, string, []FileIdentity) error { return nil },
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publication.WriteBytes(context.Background(), "first.json", []byte("four")); err != nil {
			t.Fatal(err)
		}
		if _, err := publication.WriteBytes(context.Background(), "second.json", []byte("ok")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(publication.stage, "second.json"), []byte("new"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := publication.Commit(context.Background()); err == nil {
			t.Fatal("published a stage beyond its aggregate byte limit")
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("destination exists after aggregate-stage rejection: %v", err)
		}
	})
	t.Run("file count", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "output")
		publication, err := BeginPublication(output, PublicationLimits{MaxFileBytes: 4, MaxTotalBytes: 8, MaxFiles: 1},
			func(context.Context) error { return nil },
			func(context.Context, string, []FileIdentity) error { return nil },
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("one")); err != nil {
			t.Fatal(err)
		}
		if err := WriteFile(filepath.Join(publication.stage, "extra.json"), []byte("two"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := publication.Commit(context.Background()); err == nil {
			t.Fatal("published a stage beyond its file count limit")
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("destination exists after file-count-stage rejection: %v", err)
		}
	})
}

func TestPublicationTerminalCleanupRunsOnceOnPreCommitCancellation(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output")
	ctx, cancel := context.WithCancel(context.Background())
	cleanupCalls := 0
	var publication *Publication
	publication, err := BeginPublication(output, testPublicationLimits(),
		func(cleanupContext context.Context) error {
			cleanupCalls++
			if err := cleanupContext.Err(); err != nil {
				return fmt.Errorf("cleanup inherited caller cancellation: %w", err)
			}
			return nil
		},
		func(context.Context, string, []FileIdentity) error {
			cancel()
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("result")); err != nil {
		t.Fatal(err)
	}
	stage := publication.stage
	if err := publication.Commit(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("commit error = %v, want cancellation", err)
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", cleanupCalls)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("destination exists after cancellation: %v", err)
	}
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("stage remains after cancellation: %v", err)
	}
}

func TestPublicationCommitRunsCleanupWithCanceledContext(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output")
	ctx, cancel := context.WithCancel(context.Background())
	cleanupCalls := 0
	publication, err := BeginPublication(output, testPublicationLimits(),
		func(cleanupContext context.Context) error {
			cleanupCalls++
			if err := cleanupContext.Err(); err != nil {
				return fmt.Errorf("cleanup inherited caller cancellation: %w", err)
			}
			return nil
		},
		func(context.Context, string, []FileIdentity) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("result")); err != nil {
		t.Fatal(err)
	}
	stage := publication.stage
	cancel()
	if err := publication.Commit(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("commit error = %v, want cancellation", err)
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", cleanupCalls)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("destination exists after canceled commit: %v", err)
	}
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("stage remains after canceled commit: %v", err)
	}
}

func TestPublicationStageHashStopsOnCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(path, []byte("result"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := identityForPublicationFile(ctx, path, "result.json", 8, 8); !errors.Is(err, context.Canceled) {
		t.Fatalf("stage hash error = %v, want cancellation", err)
	}
}

func TestPublicationAbortRunsCleanupOnce(t *testing.T) {
	cleanupCalls := 0
	publication, err := BeginPublication(filepath.Join(t.TempDir(), "output"), testPublicationLimits(),
		func(context.Context) error {
			cleanupCalls++
			return nil
		},
		func(context.Context, string, []FileIdentity) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	stage := publication.stage
	if err := publication.Abort(); err != nil {
		t.Fatalf("abort publication: %v", err)
	}
	if err := publication.Abort(); err != nil {
		t.Fatalf("repeat abort publication: %v", err)
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", cleanupCalls)
	}
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("stage remains after abort: %v", err)
	}
}

func TestPublicationWriteRejectsUnsafeAndDuplicatePaths(t *testing.T) {
	publication, err := BeginPublication(filepath.Join(t.TempDir(), "output"), testPublicationLimits(),
		func(context.Context) error { return nil },
		func(context.Context, string, []FileIdentity) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = publication.Abort() }()
	if _, err := publication.WriteBytes(context.Background(), "../escape.json", []byte("escape")); err == nil {
		t.Fatal("accepted an unsafe publication path")
	}
	if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("second")); err == nil {
		t.Fatal("replaced a publication file")
	}
	body, err := os.ReadFile(filepath.Join(publication.stage, "result.json"))
	if err != nil || string(body) != "first" {
		t.Fatalf("staged file = %q, %v", body, err)
	}
}

func TestPublicationCommitBlocksWhenCleanupFails(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output")
	verified := false
	publication, err := BeginPublication(output, testPublicationLimits(),
		func(context.Context) error { return errors.New("cleanup failed") },
		func(context.Context, string, []FileIdentity) error {
			verified = true
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("result")); err != nil {
		t.Fatal(err)
	}
	stage := publication.stage
	if err := publication.Commit(context.Background()); err == nil {
		t.Fatal("published despite cleanup failure")
	}
	if verified {
		t.Fatal("verified despite cleanup failure")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("destination exists after cleanup failure: %v", err)
	}
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("stage remains after cleanup failure: %v", err)
	}
	if err := publication.Abort(); err == nil {
		t.Fatal("terminal cleanup failure was not retained")
	}
}

func TestPublicationCommitRejectsStageMutationAfterVerification(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output")
	var publication *Publication
	publication, err := BeginPublication(output, testPublicationLimits(),
		func(context.Context) error { return nil },
		func(_ context.Context, stage string, _ []FileIdentity) error {
			return WriteFile(filepath.Join(stage, "added-after-verify.json"), []byte("mutation"), 0o600)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = publication.Abort() }()
	if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("result")); err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit(context.Background()); err == nil {
		t.Fatal("published a stage mutated by verification")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("destination exists after stage mutation: %v", err)
	}
}

func TestPublicationCommitRejectsLinkedStageFiles(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output")
	publication, err := BeginPublication(output, testPublicationLimits(),
		func(context.Context) error { return nil },
		func(context.Context, string, []FileIdentity) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = publication.Abort() }()
	if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("result")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(publication.stage, "result.json"), filepath.Join(publication.stage, "linked.json")); err != nil {
		t.Skipf("create stage symlink: %v", err)
	}
	if err := publication.Commit(context.Background()); err == nil {
		t.Fatal("published a stage with a symlink")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("destination exists after linked stage rejection: %v", err)
	}
}

func TestPublicationCommitRejectsExtraAndMissingFiles(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, publication *Publication)
	}{
		{
			name: "extra file",
			mutate: func(t *testing.T, publication *Publication) {
				t.Helper()
				if err := WriteFile(filepath.Join(publication.stage, "unexpected.json"), []byte("extra"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing file",
			mutate: func(t *testing.T, publication *Publication) {
				t.Helper()
				if err := os.Remove(filepath.Join(publication.stage, "result.json")); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "output")
			publication, err := BeginPublication(output, testPublicationLimits(),
				func(context.Context) error { return nil },
				func(context.Context, string, []FileIdentity) error { return nil },
			)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = publication.Abort() }()
			if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("result")); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, publication)
			if err := publication.Commit(context.Background()); err == nil {
				t.Fatal("published an invalid stage")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("destination exists after invalid stage: %v", err)
			}
		})
	}
}

func TestPublicationCommitPreservesExistingDestination(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "output")
	publication, err := BeginPublication(output, testPublicationLimits(),
		func(context.Context) error { return nil },
		func(context.Context, string, []FileIdentity) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = publication.Abort() }()
	if _, err := publication.WriteBytes(context.Background(), "result.json", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "existing.json"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit(context.Background()); err == nil {
		t.Fatal("replaced an existing destination")
	}
	body, err := os.ReadFile(filepath.Join(output, "existing.json"))
	if err != nil || string(body) != "existing" {
		t.Fatalf("existing destination = %q, %v", body, err)
	}
}

func TestPublicationCommitVerifiesOnlyTheFinalStage(t *testing.T) {
	output := filepath.Join(t.TempDir(), "output")
	cleaned := false
	var publication *Publication
	publication, err := BeginPublication(output, testPublicationLimits(),
		func(context.Context) error {
			cleaned = true
			return nil
		},
		func(_ context.Context, stage string, identities []FileIdentity) error {
			if !cleaned {
				return errors.New("verification ran before cleanup")
			}
			if stage != publication.stage {
				return fmt.Errorf("verification stage = %q, want %q", stage, publication.stage)
			}
			want := []FileIdentity{
				{Path: "a.json", Digest: digest([]byte("a")), Size: 1},
				{Path: "nested/b.json", Digest: digest([]byte("bb")), Size: 2},
			}
			if !reflect.DeepEqual(identities, want) {
				return fmt.Errorf("identities = %#v, want %#v", identities, want)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publication.WriteBytes(context.Background(), "nested/b.json", []byte("bb")); err != nil {
		t.Fatal(err)
	}
	if _, err := publication.WriteBytes(context.Background(), "a.json", []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit(context.Background()); err != nil {
		t.Fatalf("commit publication: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(output, "a.json")); err != nil {
		t.Fatalf("published a.json: %v", err)
	}
	if _, err := os.Lstat(publication.stage); !os.IsNotExist(err) {
		t.Fatalf("stage remains after commit: %v", err)
	}
}

func TestPublicationAbortRemovesPrivateStage(t *testing.T) {
	publication, err := BeginPublication(filepath.Join(t.TempDir(), "output"), testPublicationLimits(),
		func(context.Context) error { return nil },
		func(context.Context, string, []FileIdentity) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	stage := publication.stage
	if err := publication.Abort(); err != nil {
		t.Fatalf("abort publication: %v", err)
	}
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("stage remains after abort: %v", err)
	}
}

func testPublicationLimits() PublicationLimits {
	return PublicationLimits{MaxFileBytes: 1 << 20, MaxTotalBytes: 2 << 20, MaxFiles: 8}
}

func receiveAddresses(t *testing.T, addresses <-chan AttemptAddress, count int) []AttemptAddress {
	t.Helper()
	received := make([]AttemptAddress, count)
	for index := range received {
		received[index] = <-addresses
	}
	return received
}

func sameAddresses(got, want []AttemptAddress) bool {
	if len(got) != len(want) {
		return false
	}
	gotCopy := append([]AttemptAddress(nil), got...)
	wantCopy := append([]AttemptAddress(nil), want...)
	sort.Slice(gotCopy, func(left, right int) bool {
		return gotCopy[left].CellKey < gotCopy[right].CellKey || gotCopy[left].CellKey == gotCopy[right].CellKey && gotCopy[left].Repetition < gotCopy[right].Repetition
	})
	sort.Slice(wantCopy, func(left, right int) bool {
		return wantCopy[left].CellKey < wantCopy[right].CellKey || wantCopy[left].CellKey == wantCopy[right].CellKey && wantCopy[left].Repetition < wantCopy[right].Repetition
	})
	return reflect.DeepEqual(gotCopy, wantCopy)
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return fmt.Sprintf("%x", sum[:])
}

type readerFunc func([]byte) (int, error)

func (reader readerFunc) Read(buffer []byte) (int, error) {
	return reader(buffer)
}
