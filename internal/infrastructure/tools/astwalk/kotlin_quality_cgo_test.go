//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestQualityForKotlinStructuredRules(t *testing.T) {
	root := t.TempDir()
	source := `
suspend fun refresh(cache: Map<String, User>) {
    coroutineScope {
        Thread.sleep(100)
    }
    withContext(Dispatchers.IO) {
        future.get()
    }
    runCatching {
        Thread.sleep(100)
    }
    cache.get("admin")
    latch.await()
    runBlocking { fetch() }
    synchronized(lock) { fetch() }
}

fun errors(user: User) {
    try {
        work()
    } catch (failure: Exception) {
    } finally {
        return
    }
    try {
        work()
    } catch (cancelled: CancellationException) {
        logger.info("cancelled")
    }
    val name = user.name!!
    val message = "Great!!"
}

fun launched(scope: CoroutineScope) {
    scope.launch {
        Thread.sleep(100)
        future.get()
    }
}
`
	if err := os.WriteFile(filepath.Join(root, "Sample.kt"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	want := map[string]int{
		"kotlin-blocking-in-coroutine":    3,
		"kotlin-future-get-in-coroutine":  2,
		"kotlin-latch-await-in-coroutine": 1,
		"kotlin-run-blocking-in-suspend":  1,
		"kotlin-synchronized-in-suspend":  1,
		"kotlin-empty-catch":              1,
		"kotlin-return-in-finally":        1,
		"kotlin-cancellation-swallowed":   1,
		"kotlin-not-null-assertion":       1,
	}
	counts := map[string]int{}
	for _, finding := range got.Findings {
		counts[finding.Rule]++
		if finding.File != "Sample.kt" || finding.Line <= 0 || finding.Title == "" || finding.Description == "" {
			t.Errorf("incomplete finding metadata: %+v", finding)
		}
	}
	for rule, count := range want {
		if counts[rule] != count {
			t.Errorf("%s count = %d, want %d; findings=%+v", rule, counts[rule], count, got.Findings)
		}
	}
}

func TestQualityForKotlinStructuredRulesCompliant(t *testing.T) {
	root := t.TempDir()
	source := `
suspend fun refresh() {
    delay(100)
    future.await()
    coroutineScope { fetch() }
    mutex.withLock { fetch() }
}

fun errors(user: User) {
    try {
        work()
    } catch (failure: Exception) {
        logger.warn("failed", failure)
    } finally {
        cleanup()
    }
    try {
        work()
    } catch (cancelled: CancellationException) {
        throw cancelled
    }
    val name = user.name ?: return
    val message = "Great!!"
}
`
	if err := os.WriteFile(filepath.Join(root, "Safe.kts"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := QualityFor(context.Background(), root)
	if err != nil {
		t.Fatalf("QualityFor: %v", err)
	}
	structured := map[string]bool{
		"kotlin-blocking-in-coroutine": true, "kotlin-future-get-in-coroutine": true,
		"kotlin-latch-await-in-coroutine": true, "kotlin-run-blocking-in-suspend": true,
		"kotlin-synchronized-in-suspend": true, "kotlin-empty-catch": true,
		"kotlin-return-in-finally": true, "kotlin-cancellation-swallowed": true,
		"kotlin-not-null-assertion": true,
	}
	for _, finding := range got.Findings {
		if structured[finding.Rule] {
			t.Errorf("compliant Kotlin triggered %s at line %d", finding.Rule, finding.Line)
		}
	}
}
