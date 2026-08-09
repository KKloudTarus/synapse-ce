package fleetclient

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadEnrolTokenFile(t *testing.T) {
	dir := t.TempDir()

	t.Run("no path configured is not an error", func(t *testing.T) {
		tok, err := ReadEnrolTokenFile("")
		if err != nil || tok != "" {
			t.Fatalf("got (%q, %v), want empty and no error", tok, err)
		}
	})

	// The case the Kubernetes deployment depends on. After enrolment the one-time Secret is dead
	// weight, so an operator deleting it is right; if that made this fatal, the pod could never
	// restart even though its credential is on the state volume.
	t.Run("an absent file is not an error, because a spent token gets deleted", func(t *testing.T) {
		tok, err := ReadEnrolTokenFile(filepath.Join(dir, "does-not-exist"))
		if err != nil {
			t.Fatalf("absent file must not be an error, got %v", err)
		}
		if tok != "" {
			t.Fatalf("got token %q from an absent file", tok)
		}
	})

	t.Run("a token is read and trimmed", func(t *testing.T) {
		path := filepath.Join(dir, "token")
		// Trailing newlines are what `kubectl create secret --from-file` and shell redirection produce;
		// an untrimmed token fails enrolment with an authentication error that looks like a bad secret.
		if err := os.WriteFile(path, []byte("  one-time-token-value\n\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		tok, err := ReadEnrolTokenFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if tok != "one-time-token-value" {
			t.Fatalf("got %q, want the trimmed token", tok)
		}
	})

	// A file that exists but cannot be read is a MISCONFIGURATION, and must not be silently reported as
	// "no token": that would surface far away as an unexplained enrolment failure.
	t.Run("a directory in place of the file is an error", func(t *testing.T) {
		path := filepath.Join(dir, "as-a-directory")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadEnrolTokenFile(path); err == nil {
			t.Fatal("want an error when the path is a directory, got nil")
		}
	})

	t.Run("an unreadable file is an error, not an absent token", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows uses ACLs, not permission bits; os.Chmod cannot make a file unreadable here")
		}
		if os.Geteuid() == 0 {
			t.Skip("root bypasses permission bits, so this case cannot be provoked")
		}
		path := filepath.Join(dir, "unreadable")
		if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o000); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadEnrolTokenFile(path); err == nil {
			t.Fatal("want an error for an existing but unreadable file, got nil")
		}
	})
}
