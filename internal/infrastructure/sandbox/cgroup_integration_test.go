//go:build linux

package sandbox_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const bombC = `
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char**argv){
  if(argc>1 && !strcmp(argv[1],"fork")){
    int n=0; for(int i=0;i<5000;i++){ pid_t p=fork(); if(p==0){pause();_exit(0);} if(p<0) break; n++; }
    printf("forked=%d\n",n); fflush(stdout); return 0;
  }
  if(argc>1 && !strcmp(argv[1],"mem")){
    size_t step=16*1024*1024;
    for(int i=0;i<64;i++){ char*b=malloc(step); if(!b){printf("malloc_fail\n");return 0;} memset(b,1,step); printf("alloced=%dMB\n",(i+1)*16); fflush(stdout); }
    return 0;
  }
  return 0;
}
`

// TestCgroupContainsForkBomb proves F3: pids.max bounds a fork bomb on the egress path
// (the privileged path that touches hostile networks). Needs bwrap + gcc + cgroup write.
func TestCgroupContainsBombs(t *testing.T) {
	for _, b := range []string{"bwrap", "gcc"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not installed", b)
		}
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("cgroup v2 not mounted")
	}
	sb, err := sandbox.NewRunner(30*time.Second, 8<<20, 1<<30, 512)
	if err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "bomb.c"), []byte(bombC), 0o644)
	bomb := filepath.Join(dir, "bomb")
	if out, err := exec.Command("gcc", "-O0", "-o", bomb, filepath.Join(dir, "bomb.c")).CombinedOutput(); err != nil {
		t.Fatalf("compile bomb: %v\n%s", err, out)
	}
	ctx := context.Background()

	// Fork bomb under pids.max=64: forks are capped far below the 5000 attempted.
	res, err := sb.Run(ctx, ports.ToolSpec{Name: bomb, Args: []string{"fork"}, Workdir: dir, PidsMax: 64})
	if err != nil {
		t.Fatalf("fork run: %v", err)
	}
	forked := 99999
	if m := regexp.MustCompile(`forked=(\d+)`).FindStringSubmatch(string(res.Stdout)); m != nil {
		forked, _ = strconv.Atoi(m[1])
	}
	t.Logf("fork bomb: forked=%d (pids.max=64)", forked)
	if forked >= 500 {
		t.Fatalf("fork bomb NOT contained: forked=%d (pids.max should cap ~64)", forked)
	}

	// Memory bomb under memory.max=64MB: OOM-killed long before allocating 1GB.
	res, _ = sb.Run(ctx, ports.ToolSpec{Name: bomb, Args: []string{"mem"}, Workdir: dir, MemMaxBytes: 64 << 20})
	high := 0
	for _, m := range regexp.MustCompile(`alloced=(\d+)MB`).FindAllStringSubmatch(string(res.Stdout), -1) {
		if v, _ := strconv.Atoi(m[1]); v > high {
			high = v
		}
	}
	t.Logf("memory bomb: high-water=%dMB (memory.max=64MB), exit=%d", high, res.ExitCode)
	if high >= 256 {
		t.Fatalf("memory bomb NOT contained: reached %dMB under a 64MB cap", high)
	}
	if strings.Contains(string(res.Stdout), "alloced=1024MB") {
		t.Fatal("memory bomb ran to completion – cgroup memory.max not enforced")
	}
}
