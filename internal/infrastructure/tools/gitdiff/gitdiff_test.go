package gitdiff

import "testing"

func TestParseDiff(t *testing.T) {
	diff := "diff --git a/x.go b/x.go\n" +
		"--- a/x.go\n" +
		"+++ b/x.go\n" +
		"@@ -1,0 +2,3 @@\n+a\n+b\n+c\n" + // adds lines 2,3,4
		"@@ -20 +25 @@\n-old\n+new\n" + // adds line 25 (count omitted = 1)
		"diff --git a/y.py b/y.py\n" +
		"--- a/y.py\n" +
		"+++ b/y.py\n" +
		"@@ -5,2 +5,0 @@\n-gone1\n-gone2\n" // pure deletion: adds nothing
	c := parseDiff([]byte(diff))

	for _, ln := range []int{2, 3, 4, 25} {
		if !c.Has("x.go", ln) {
			t.Errorf("x.go line %d should be changed", ln)
		}
	}
	for _, ln := range []int{1, 5, 24, 26} {
		if c.Has("x.go", ln) {
			t.Errorf("x.go line %d should NOT be changed", ln)
		}
	}
	if len(c["y.py"]) != 0 {
		t.Errorf("y.py pure-deletion hunk must add no lines, got %v", c["y.py"])
	}
}

func TestParseDiffEmpty(t *testing.T) {
	if len(parseDiff(nil)) != 0 {
		t.Error("empty diff should yield no changed files")
	}
}
