package sast

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The per-file finding budget is shared by no class. One file on a real repository reached the cap at
// exactly 50 findings, every one of them maintainability, which means a security weakness below that point
// was dropped for want of budget spent on formatting. A file whose style findings fill the share must still
// report the weakness under them.
func TestPerFileBudgetDoesNotLetStyleCrowdOutSecurity(t *testing.T) {
	var src strings.Builder
	src.WriteString("<?php\n")
	// Well past maxFindingsPerFile worth of a maintainability rule: two statements on one line.
	for i := 0; i < maxFindingsPerFile+20; i++ {
		src.WriteString("$a" + strconv.Itoa(i) + " = 1; $b" + strconv.Itoa(i) + " = 2;\n")
	}
	// The security weakness sits BELOW every one of them.
	src.WriteString("$out = shell_exec($_GET['cmd']);\n")

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "handler.php"), []byte(src.String()), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	findings, err := New().AnalyzeSource(context.Background(), root)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	var security, quality int
	for _, f := range findings {
		if isSecurityFinding(f) {
			security++
		} else {
			quality++
		}
	}
	if security == 0 {
		t.Errorf("the weakness below %d style findings must still be reported; got %d security, %d quality",
			maxFindingsPerFile, security, quality)
	}
	if quality > maxFindingsPerFile {
		t.Errorf("the quality class must stay within its own per-file share: got %d, cap %d", quality, maxFindingsPerFile)
	}
}
