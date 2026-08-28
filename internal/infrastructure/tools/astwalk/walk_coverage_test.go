package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWalkSourceWithIssuesReportsSkippedPythonCandidates(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "large.py"), make([]byte, maxFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "broken.ipynb"), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}

	var issues []sourceIssue
	truncated, err := walkSourceWithIssues(context.Background(), root, func(string, string, []byte) {
		t.Fatal("unparseable candidate must not be visited")
	}, func(issue sourceIssue) {
		issues = append(issues, issue)
	})
	if err != nil || truncated {
		t.Fatalf("walk: truncated=%v err=%v", truncated, err)
	}
	if !hasSourceIssue(issues, "large.py", sourceIssueOversized) {
		t.Errorf("missing oversized issue: %+v", issues)
	}
	if !hasSourceIssue(issues, "broken.ipynb", sourceIssueMalformedNotebook) {
		t.Errorf("missing malformed notebook issue: %+v", issues)
	}
}

func TestWalkSourceWithIssuesVisitsPythonByExtension(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "script.py"), []byte("value = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	visited := false
	var issues []sourceIssue
	_, err := walkSourceWithIssues(context.Background(), root, func(rel, lang string, _ []byte) {
		visited = rel == "script.py" && lang == "Python"
	}, func(issue sourceIssue) {
		issues = append(issues, issue)
	})
	if err != nil || !visited || len(issues) != 0 {
		t.Fatalf("walk: visited=%v issues=%+v err=%v", visited, issues, err)
	}
}

func hasSourceIssue(issues []sourceIssue, rel string, reason sourceIssueReason) bool {
	for _, issue := range issues {
		if issue.Rel == rel && issue.Reason == reason {
			return true
		}
	}
	return false
}
