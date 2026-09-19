package reachbench

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	hostileGitHelperEnvironment = "SYNAPSE_REACHABILITY_HOSTILE_GIT_HELPER"
	hostileGitMarkerEnvironment = "SYNAPSE_REACHABILITY_HOSTILE_GIT_MARKER"
)

func TestMain(m *testing.M) {
	if os.Getenv(hostileGitHelperEnvironment) == "1" {
		if err := os.WriteFile(os.Getenv(hostileGitMarkerEnvironment), []byte("executed\n"), 0o600); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type realAuthorityRepository struct {
	root     string
	baseline string
}

func TestAuthorityCuratorCommittedCandidateAuthorityRealGit(t *testing.T) {
	files := validCandidateAuthorityFiles(t)

	t.Run("tracked exact inventory succeeds", func(t *testing.T) {
		repository := newRealAuthorityRepository(t, files)
		output := authorityOutput(t)
		if err := newRealAuthorityCurator(t, repository).PrepareCandidate(context.Background(), output); err != nil {
			t.Fatal(err)
		}
		if got := sortedAuthorityPaths(authorityFileBytes(t, output)); len(got) != 8 {
			t.Fatalf("published controller inventory = %q", got)
		}
		subject, _, subjectRef, err := readControllerCandidateReviewSubject(context.Background(), output)
		if err != nil {
			t.Fatal(err)
		}
		commit := runTestGit(t, repository.root, "rev-parse", "HEAD")
		tree := runTestGit(t, repository.root, "rev-parse", "HEAD^{tree}")
		capture, err := newRealAuthorityCurator(t, repository).captureCommittedCandidateAuthorityFiles(context.Background(), realAuthorityCheckout(t, repository.root))
		if err != nil {
			t.Fatal(err)
		}
		if subject.Harness != (HarnessIdentity{ID: ReviewedHarnessID, Commit: commit, Tree: tree}) || subject.AuthorityInventoryDigest != capture.inventoryDigest {
			t.Fatalf("candidate review subject did not bind final committed authority: %+v", subject)
		}
		var envelope RunEnvelope
		if _, err := readCanonicalJSON(filepath.Join(output, authorityEnvelopeDirectory, "candidate-"+commit+".json"), &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Authority.ReviewEvidence != subjectRef {
			t.Fatalf("candidate envelope review reference = %+v, want %+v", envelope.Authority.ReviewEvidence, subjectRef)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, repository realAuthorityRepository)
		want   string
	}{
		{
			name: "untracked authority file",
			mutate: func(t *testing.T, repository realAuthorityRepository) {
				t.Helper()
				writeTestFile(t, filepath.Join(repository.root, filepath.FromSlash(TrustedBundleRelativePath), "untracked.json"), []byte("{}\n"))
			},
			want: "pristine checkout",
		},
		{
			name: "missing authority blob",
			mutate: func(t *testing.T, repository realAuthorityRepository) {
				t.Helper()
				if err := os.Remove(filepath.Join(repository.root, filepath.FromSlash(TrustedBundleRelativePath), "candidate-input.json")); err != nil {
					t.Fatal(err)
				}
				runTestGit(t, repository.root, "add", "-A")
				runTestGit(t, repository.root, "commit", "-m", "remove candidate authority blob")
			},
			want: "inventory is not exact",
		},
		{
			name: "extra authority blob",
			mutate: func(t *testing.T, repository realAuthorityRepository) {
				t.Helper()
				writeTestFile(t, filepath.Join(repository.root, filepath.FromSlash(TrustedBundleRelativePath), "extra.json"), []byte("{}\n"))
				runTestGit(t, repository.root, "add", "-A")
				runTestGit(t, repository.root, "commit", "-m", "add extra candidate authority blob")
			},
			want: "inventory is not exact",
		},
		{
			name: "non ordinary mode",
			mutate: func(t *testing.T, repository realAuthorityRepository) {
				t.Helper()
				path := TrustedBundleRelativePath + "/baseline-input.json"
				runTestGit(t, repository.root, "update-index", "--chmod=+x", "--", path)
				runTestGit(t, repository.root, "commit", "-m", "make candidate authority executable")
				if err := os.Chmod(filepath.Join(repository.root, filepath.FromSlash(path)), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: "ordinary 100644 blobs",
		},
		{
			name: "replacement refs",
			mutate: func(t *testing.T, repository realAuthorityRepository) {
				t.Helper()
				runTestGit(t, repository.root, "replace", repository.baseline, "HEAD")
			},
			want: "replacement refs",
		},
		{
			name: "legacy graft file",
			mutate: func(t *testing.T, repository realAuthorityRepository) {
				t.Helper()
				head := runTestGit(t, repository.root, "rev-parse", "HEAD")
				writeTestFile(t, filepath.Join(repository.root, ".git", "info", "grafts"), []byte(head+" "+repository.baseline+"\n"))
			},
			want: "Git graft files",
		},
		{
			name: "assume unchanged authority index",
			mutate: func(t *testing.T, repository realAuthorityRepository) {
				t.Helper()
				runTestGit(t, repository.root, "update-index", "--assume-unchanged", "--", TrustedBundleRelativePath+"/baseline-input.json")
			},
			want: "hidden or ambiguous Git index state",
		},
		{
			name: "skip worktree authority index",
			mutate: func(t *testing.T, repository realAuthorityRepository) {
				t.Helper()
				runTestGit(t, repository.root, "update-index", "--skip-worktree", "--", TrustedBundleRelativePath+"/baseline-input.json")
			},
			want: "hidden or ambiguous Git index state",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := newRealAuthorityRepository(t, files)
			test.mutate(t, repository)
			output := authorityOutput(t)
			err := newRealAuthorityCurator(t, repository).PrepareCandidate(context.Background(), output)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("PrepareCandidate() error = %v, want %q", err, test.want)
			}
			assertAuthorityOutputAbsent(t, output)
		})
	}

	t.Run("inherited Git environment is ignored", func(t *testing.T) {
		repository := newRealAuthorityRepository(t, files)
		t.Setenv("GIT_DIR", filepath.Join(t.TempDir(), "untrusted-git-dir"))
		t.Setenv("GIT_CONFIG_COUNT", "1")
		t.Setenv("GIT_CONFIG_KEY_0", "core.worktree")
		t.Setenv("GIT_CONFIG_VALUE_0", t.TempDir())
		output := authorityOutput(t)
		if err := newRealAuthorityCurator(t, repository).PrepareCandidate(context.Background(), output); err != nil {
			t.Fatalf("sanitized Git environment failed candidate preparation: %v", err)
		}
	})

	t.Run("candidate path cannot enter Git metadata", func(t *testing.T) {
		repository := newRealAuthorityRepository(t, files)
		if _, err := authorityDirectoryInCheckout(context.Background(), repository.root, ".git"); err == nil || !strings.Contains(err.Error(), ".git") {
			t.Fatalf("Git metadata authority path error = %v", err)
		}
	})

	t.Run("candidate path rejects ancestor symlink", func(t *testing.T) {
		repository := newRealAuthorityRepository(t, files)
		outside := t.TempDir()
		internal := filepath.Join(repository.root, "internal")
		if err := os.Rename(internal, filepath.Join(outside, "internal")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(outside, "internal"), internal); err != nil {
			t.Skipf("create ancestor symlink: %v", err)
		}
		if _, err := authorityDirectoryInCheckout(context.Background(), repository.root, TrustedBundleRelativePath); err == nil || !strings.Contains(err.Error(), "symlink or reparse") {
			t.Fatalf("ancestor symlink authority path error = %v", err)
		}
	})

	t.Run("changed head before publication leaves no output", func(t *testing.T) {
		repository := newRealAuthorityRepository(t, files)
		statusCalls := 0
		curator := newRealAuthorityCuratorWithHook(t, repository, func(args []string) {
			if strings.Contains(strings.Join(args, "\x00"), "status\x00--porcelain=v1") {
				statusCalls++
				if statusCalls == 2 {
					writeTestFile(t, filepath.Join(repository.root, "after-capture.txt"), []byte("changed head\n"))
					runTestGit(t, repository.root, "add", "after-capture.txt")
					runTestGit(t, repository.root, "commit", "-m", "change head after candidate capture")
				}
			}
		})
		output := authorityOutput(t)
		err := curator.PrepareCandidate(context.Background(), output)
		if err == nil || !strings.Contains(err.Error(), "checkout changed before publication") {
			t.Fatalf("changed HEAD error = %v", err)
		}
		assertAuthorityOutputAbsent(t, output)
	})

	t.Run("changed authority bytes before publication leaves no output", func(t *testing.T) {
		repository := newRealAuthorityRepository(t, files)
		statusCalls := 0
		curator := newRealAuthorityCuratorWithHook(t, repository, func(args []string) {
			if strings.Contains(strings.Join(args, "\x00"), "status\x00--porcelain=v1") {
				statusCalls++
				if statusCalls == 2 {
					writeTestFile(t, filepath.Join(repository.root, filepath.FromSlash(TrustedBundleRelativePath), "baseline-input.json"), []byte("{}\n"))
				}
			}
		})
		output := authorityOutput(t)
		err := curator.PrepareCandidate(context.Background(), output)
		if err == nil || !strings.Contains(err.Error(), "pristine checkout") {
			t.Fatalf("changed authority bytes error = %v", err)
		}
		assertAuthorityOutputAbsent(t, output)
	})

	t.Run("cancellation leaves no destination or private stage", func(t *testing.T) {
		repository := newRealAuthorityRepository(t, files)
		output := authorityOutput(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := newRealAuthorityCurator(t, repository).PrepareCandidate(ctx, output)
		if err == nil || ctx.Err() == nil {
			t.Fatalf("canceled candidate preparation error = %v", err)
		}
		assertAuthorityOutputAbsent(t, output)
		entries, readErr := os.ReadDir(filepath.Dir(output))
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".output.stage-") {
				t.Fatalf("canceled preparation left private stage %q", entry.Name())
			}
		}
	})
}

func TestAuthorityCuratorRejectsHostileLocalGitConfigurationBeforeCuration(t *testing.T) {
	files := validCandidateAuthorityFiles(t)
	for _, test := range []struct {
		name  string
		key   string
		value func(t *testing.T, repository realAuthorityRepository) string
	}{
		{
			name: "fsmonitor command",
			key:  "core.fsmonitor",
			value: func(t *testing.T, _ realAuthorityRepository) string {
				t.Helper()
				return os.Args[0]
			},
		},
		{
			name: "hooks path",
			key:  "core.hooksPath",
			value: func(t *testing.T, _ realAuthorityRepository) string {
				t.Helper()
				return t.TempDir()
			},
		},
		{
			name: "conditional include",
			key:  "includeIf.gitdir:*/.path",
			value: func(t *testing.T, _ realAuthorityRepository) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "included.gitconfig")
			},
		},
		{
			name: "worktree indirection",
			key:  "core.worktree",
			value: func(t *testing.T, repository realAuthorityRepository) string {
				t.Helper()
				return filepath.Join(repository.root, "untrusted-worktree")
			},
		},
		{
			name: "worktree config extension",
			key:  "extensions.worktreeConfig",
			value: func(t *testing.T, _ realAuthorityRepository) string {
				t.Helper()
				return "true"
			},
		},
		{
			name: "external diff command",
			key:  "diff.external",
			value: func(t *testing.T, _ realAuthorityRepository) string {
				t.Helper()
				return os.Args[0]
			},
		},
		{
			name: "alternate refs command",
			key:  "core.alternateRefsCommand",
			value: func(t *testing.T, _ realAuthorityRepository) string {
				t.Helper()
				return os.Args[0]
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := newRealAuthorityRepository(t, files)
			marker := filepath.Join(t.TempDir(), "hostile-git-command-ran")
			t.Setenv(hostileGitHelperEnvironment, "1")
			t.Setenv(hostileGitMarkerEnvironment, marker)
			runTestGit(t, repository.root, "config", "--local", test.key, test.value(t, repository))

			output := authorityOutput(t)
			err := newRealAuthorityCurator(t, repository).PrepareCandidate(context.Background(), output)
			if err == nil || !strings.Contains(err.Error(), "unsafe Git configuration") {
				t.Fatalf("PrepareCandidate() error = %v, want unsafe local configuration rejection", err)
			}
			if _, err := os.Lstat(marker); !os.IsNotExist(err) {
				t.Fatalf("hostile local Git configuration executed a command: %v", err)
			}
			assertAuthorityOutputAbsent(t, output)
		})
	}
}

func TestAuthorityPublicationCancellationRemovesPrivateStage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := authorityOutput(t)
	err := (&AuthorityCurator{}).publishAuthority(ctx, output, nil, []authorityAsset{{path: "artifact.json", body: []byte("{}\n")}}, func(context.Context) error {
		cancel()
		return nil
	}, func(context.Context, string) error {
		t.Fatal("canceled publication reached stage verification")
		return nil
	})
	if err == nil || ctx.Err() == nil {
		t.Fatalf("canceled authority publication error = %v", err)
	}
	assertAuthorityOutputAbsent(t, output)
	entries, readErr := os.ReadDir(filepath.Dir(output))
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".output.stage-") {
			t.Fatalf("canceled publication left private stage %q", entry.Name())
		}
	}
}

func TestCommittedCandidateAuthorityTreeRejectsLinkAndGitlinkEntries(t *testing.T) {
	files := validCandidateAuthorityFiles(t)
	for _, test := range []struct {
		name string
		mode string
	}{
		{name: "symlink", mode: "120000"},
		{name: "gitlink", mode: "160000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := newRealAuthorityRepository(t, files)
			path := TrustedBundleRelativePath + "/baseline-input.json"
			object := runTestGit(t, repository.root, "rev-parse", "HEAD")
			runTestGit(t, repository.root, "update-index", "--add", "--cacheinfo", test.mode+","+object+","+path)
			runTestGit(t, repository.root, "commit", "-m", "replace authority blob with non-blob entry")
			checkout := realAuthorityCheckout(t, repository.root)
			_, err := newRealAuthorityCurator(t, repository).captureCommittedCandidateAuthorityFiles(context.Background(), checkout)
			if err == nil || !strings.Contains(err.Error(), "ordinary 100644 blobs") {
				t.Fatalf("capture committed authority error = %v", err)
			}
		})
	}
}

func validCandidateAuthorityFiles(t *testing.T) map[string][]byte {
	t.Helper()
	_, curatorGit, baselineAuthority, publication, review := curatedBaseline(t)
	candidate := authorityOutput(t)
	disposition := writeDispositionEvidence(t, "candidate-disposition.json", "candidate-disposition", publication)
	if err := curatorGit.curator(t).DeriveCandidate(context.Background(), publication, baselineAuthority, review, disposition, candidate); err != nil {
		t.Fatal(err)
	}
	return authorityFileBytes(t, candidate)
}

func newRealAuthorityRepository(t *testing.T, files map[string][]byte) realAuthorityRepository {
	t.Helper()
	root := t.TempDir()
	runTestGit(t, root, "init")
	runTestGit(t, root, "config", "user.email", "authority@example.test")
	runTestGit(t, root, "config", "user.name", "Authority Test")
	writeTestFile(t, filepath.Join(root, "README"), []byte("baseline\n"))
	runTestGit(t, root, "add", "README")
	runTestGit(t, root, "commit", "-m", "baseline")
	baseline := runTestGit(t, root, "rev-parse", "HEAD")
	for relative, body := range files {
		writeTestFile(t, filepath.Join(root, filepath.FromSlash(TrustedBundleRelativePath), filepath.FromSlash(relative)), body)
	}
	runTestGit(t, root, "add", "--", TrustedBundleRelativePath)
	runTestGit(t, root, "commit", "-m", "add candidate authority")
	return realAuthorityRepository{root: root, baseline: baseline}
}

func newRealAuthorityCurator(t *testing.T, repository realAuthorityRepository) *AuthorityCurator {
	t.Helper()
	return newRealAuthorityCuratorWithHook(t, repository, nil)
}

func newRealAuthorityCuratorWithHook(t *testing.T, repository realAuthorityRepository, hook func([]string)) *AuthorityCurator {
	t.Helper()
	if info, err := os.Stat(filepath.Join(repository.root, ".git")); err != nil || !info.IsDir() {
		t.Fatalf("real authority test repository has no Git directory: %v", err)
	}
	curator, err := newAuthorityCurator(AuthorityCuratorDependencies{
		Command: func(ctx context.Context, binary string, args ...string) ([]byte, error) {
			if hook != nil {
				hook(args)
			}
			invocation := append([]string(nil), args...)
			if !containsGitDirectoryFlag(invocation) {
				invocation = append([]string{"-C", repository.root}, invocation...)
			}
			command := exec.CommandContext(ctx, binary, invocation...)
			command.Env = authorityGitEnvironment()
			return command.Output()
		},
	}, repository.baseline)
	if err != nil {
		t.Fatal(err)
	}
	return curator
}

func realAuthorityCheckout(t *testing.T, root string) authorityCheckout {
	t.Helper()
	commit := runTestGit(t, root, "rev-parse", "HEAD")
	tree := runTestGit(t, root, "rev-parse", commit+"^{tree}")
	return authorityCheckout{root: root, harness: HarnessIdentity{ID: ReviewedHarnessID, Commit: commit, Tree: tree}}
}

func containsGitDirectoryFlag(args []string) bool {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "-C" {
			return true
		}
	}
	return false
}

func runTestGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = authorityGitEnvironment()
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func writeTestFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
