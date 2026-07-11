package gradleresolve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeJDK(t *testing.T) string {
	t.Helper()
	jdk := t.TempDir()
	if err := os.MkdirAll(filepath.Join(jdk, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, exe := range []string{"java", "javac"} { // a JDK has both; javaHomeValid requires the compiler
		if err := os.WriteFile(filepath.Join(jdk, "bin", exe), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return jdk
}

func TestJavaHomeValid(t *testing.T) {
	if !javaHomeValid(makeJDK(t)) {
		t.Errorf("a dir with bin/java must be a valid JAVA_HOME")
	}
	if javaHomeValid(t.TempDir()) {
		t.Errorf("an empty dir must not be a valid JAVA_HOME")
	}
	if javaHomeValid("") {
		t.Errorf("empty string must not be valid")
	}
	// A JRE (java but no javac) must be rejected – Gradle needs a JDK.
	jre := t.TempDir()
	if err := os.MkdirAll(filepath.Join(jre, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jre, "bin", "java"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if javaHomeValid(jre) {
		t.Errorf("a JRE (no javac) must not be accepted as a JDK")
	}
}

func TestEnsureJavaHome(t *testing.T) {
	jdk := makeJDK(t)

	// A valid JAVA_HOME is kept and detect() is never consulted.
	env := ensureJavaHome([]string{"PATH=/usr/bin", "JAVA_HOME=" + jdk}, func() string {
		t.Fatal("detect must not run when JAVA_HOME is already valid")
		return ""
	})
	if envValue(env, "JAVA_HOME") != jdk {
		t.Errorf("valid JAVA_HOME should be kept, got %q", envValue(env, "JAVA_HOME"))
	}

	// An invalid JAVA_HOME is replaced by the detected JDK, with exactly one JAVA_HOME entry.
	env = ensureJavaHome([]string{"PATH=/usr/bin", "JAVA_HOME=/does/not/exist"}, func() string { return jdk })
	if envValue(env, "JAVA_HOME") != jdk {
		t.Errorf("invalid JAVA_HOME should be replaced with %q, got %q", jdk, envValue(env, "JAVA_HOME"))
	}
	n := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, "JAVA_HOME=") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("want exactly one JAVA_HOME entry after replace, got %d", n)
	}

	// A missing JAVA_HOME with a detected JDK gets it set.
	env = ensureJavaHome([]string{"PATH=/usr/bin"}, func() string { return jdk })
	if envValue(env, "JAVA_HOME") != jdk {
		t.Errorf("missing JAVA_HOME should be set to detected JDK")
	}

	// Nothing detected + invalid current => left unchanged (Gradle surfaces its own error).
	env = ensureJavaHome([]string{"JAVA_HOME=/does/not/exist"}, func() string { return "" })
	if envValue(env, "JAVA_HOME") != "/does/not/exist" {
		t.Errorf("should be unchanged when detect finds nothing, got %q", envValue(env, "JAVA_HOME"))
	}
}
