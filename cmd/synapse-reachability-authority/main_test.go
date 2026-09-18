package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestExecuteCLIAcceptsOnlyCuratorPaths(t *testing.T) {
	ctx := context.Background()
	var preparedBaseline []string
	code := executeCLI(
		ctx,
		[]string{"prepare-baseline", "review.json", "output"},
		&bytes.Buffer{},
		&bytes.Buffer{},
		func(_ context.Context, review, output string) error {
			preparedBaseline = []string{review, output}
			return nil
		},
		func(context.Context, string, string, string, string, string) error {
			t.Fatal("derive must not run")
			return nil
		},
		func(context.Context, string) error {
			t.Fatal("prepare candidate must not run")
			return nil
		},
	)
	if code != 0 || !reflect.DeepEqual(preparedBaseline, []string{"review.json", "output"}) {
		t.Fatalf("prepare-baseline code = %d, paths = %#v", code, preparedBaseline)
	}

	var derived []string
	code = executeCLI(
		ctx,
		[]string{"derive-candidate", "publication", "baseline-authority", "review.json", "disposition.json", "output"},
		&bytes.Buffer{},
		&bytes.Buffer{},
		func(context.Context, string, string) error {
			t.Fatal("prepare baseline must not run")
			return nil
		},
		func(_ context.Context, publication, authority, review, disposition, output string) error {
			derived = []string{publication, authority, review, disposition, output}
			return nil
		},
		func(context.Context, string) error {
			t.Fatal("prepare candidate must not run")
			return nil
		},
	)
	if code != 0 || !reflect.DeepEqual(derived, []string{"publication", "baseline-authority", "review.json", "disposition.json", "output"}) {
		t.Fatalf("derive-candidate code = %d, paths = %#v", code, derived)
	}

	var preparedCandidate []string
	code = executeCLI(
		ctx,
		[]string{"prepare-candidate", "output"},
		&bytes.Buffer{},
		&bytes.Buffer{},
		func(context.Context, string, string) error {
			t.Fatal("prepare baseline must not run")
			return nil
		},
		func(context.Context, string, string, string, string, string) error {
			t.Fatal("derive must not run")
			return nil
		},
		func(_ context.Context, output string) error {
			preparedCandidate = []string{output}
			return nil
		},
	)
	if code != 0 || !reflect.DeepEqual(preparedCandidate, []string{"output"}) {
		t.Fatalf("prepare-candidate code = %d, paths = %#v", code, preparedCandidate)
	}
}

func TestExecuteCLIRejectsArgumentsOutsidePathContract(t *testing.T) {
	called := false
	prepare := func(context.Context, string, string) error {
		called = true
		return nil
	}
	derive := func(context.Context, string, string, string, string, string) error {
		called = true
		return nil
	}
	candidate := func(context.Context, string) error {
		called = true
		return nil
	}
	for _, args := range [][]string{
		nil,
		{"prepare-baseline", "--implementation-sha", "review.json", "output"},
		{"derive-candidate", "publication", "authority", "review.json", "disposition.json"},
		{"prepare-candidate", "candidate-authority", "output"},
		{"unknown", "review.json", "output"},
	} {
		stderr := &bytes.Buffer{}
		if code := executeCLI(context.Background(), args, &bytes.Buffer{}, stderr, prepare, derive, candidate); code != 1 || called || stderr.Len() == 0 {
			t.Fatalf("args %#v: code = %d, called = %t, stderr = %q", args, code, called, stderr.String())
		}
	}
}

func TestExecuteCLIReportsCuratorFailure(t *testing.T) {
	stderr := &bytes.Buffer{}
	code := executeCLI(
		context.Background(),
		[]string{"prepare-candidate", "output"},
		&bytes.Buffer{},
		stderr,
		func(context.Context, string, string) error { return nil },
		func(context.Context, string, string, string, string, string) error { return nil },
		func(context.Context, string) error { return errors.New("candidate authority is invalid") },
	)
	if code != 1 || !bytes.Contains(stderr.Bytes(), []byte("candidate authority is invalid")) {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

func TestExecuteCLIDescribesUnsignedPreparation(t *testing.T) {
	stdout := &bytes.Buffer{}
	code := executeCLI(
		context.Background(),
		[]string{"prepare-candidate", "output"},
		stdout,
		&bytes.Buffer{},
		func(context.Context, string, string) error { return nil },
		func(context.Context, string, string, string, string, string) error { return nil },
		func(context.Context, string) error { return nil },
	)
	if code != 0 || !bytes.Contains(stdout.Bytes(), []byte("unsigned, non-authoritative")) || !bytes.Contains(stdout.Bytes(), []byte("external detached review signatures")) {
		t.Fatalf("prepare output = %q", stdout.String())
	}
}

func TestExecuteCLIRejectsNilContext(t *testing.T) {
	stderr := &bytes.Buffer{}
	if code := executeCLI(nil, []string{"prepare-baseline", "review.json", "output"}, &bytes.Buffer{}, stderr, nil, nil, nil); code != 1 || stderr.Len() == 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}
