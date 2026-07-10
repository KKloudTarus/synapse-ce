//go:build linux

package sandbox_test

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/egress"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// redteamC attempts a battery of escapes/leaks from inside the sandbox and prints the
// result of each so the auditor judges on OBSERVED behavior, not claims.
const redteamC = `
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <arpa/inet.h>

static void rd(const char*label,const char*path){
  int fd=open(path,O_RDONLY); 
  if(fd<0){printf("READ %-28s DENIED errno=%d\n",label,errno);return;}
  char b[64]={0}; int n=read(fd,b,40); close(fd);
  printf("READ %-28s OPENED n=%d first=\"%.20s\"\n",label,n,n>0?b:"");
}
static void sc(const char*label,long nr,long a1,long a2){
  errno=0; long r=syscall(nr,a1,a2,0,0,0,0);
  printf("SYS  %-28s rc=%ld errno=%d\n",label,r,errno);
}
static void sock(const char*label,int dom,int typ,int proto){
  errno=0; int s=socket(dom,typ,proto);
  printf("SOCK %-28s rc=%d errno=%d\n",label,s,errno); if(s>=0)close(s);
}
static void tcp(const char*label,const char*ip,int port){
  int v6=strchr(ip,':')!=NULL;
  int s=socket(v6?AF_INET6:AF_INET,SOCK_STREAM,0);
  if(s<0){printf("CONN %-28s SOCKFAIL errno=%d\n",label,errno);return;}
  struct timeval tv={3,0}; setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof tv);
  int rc;
  if(v6){struct sockaddr_in6 a={0};a.sin6_family=AF_INET6;a.sin6_port=htons(port);inet_pton(AF_INET6,ip,&a.sin6_addr);rc=connect(s,(void*)&a,sizeof a);}
  else  {struct sockaddr_in  a={0};a.sin_family=AF_INET; a.sin_port=htons(port); inet_pton(AF_INET,ip,&a.sin_addr); rc=connect(s,(void*)&a,sizeof a);}
  printf("CONN %-28s rc=%d errno=%d\n",label,rc,errno); close(s);
}
int main(int argc,char**argv){
  // --- filesystem discovery ---
  DIR*d=opendir("/"); char dirs[256]={0}; struct dirent*e;
  if(d){while((e=readdir(d))){if(e->d_name[0]!='.'){strncat(dirs,e->d_name,20);strcat(dirs," ");}}closedir(d);}
  printf("ROOTDIRS %s\n",dirs);
  printf("SYS_PRESENT %d\n", access("/sys",F_OK)==0);
  // --- host secret reads ---
  rd("/etc/shadow","/etc/shadow");
  rd("/root/.ssh/redteam_canary","/root/.ssh/redteam_canary");
  rd("/etc/ssl_private","/etc/ssl/private");
  rd("/proc/1/environ","/proc/1/environ");
  // --- env leakage (own env) ---
  {int fd=open("/proc/self/environ",O_RDONLY);char b[4096]={0};int n=fd>=0?read(fd,b,sizeof b-1):0;if(fd>=0)close(fd);
   int leak=0;for(int i=0;i<n;i++){if(!strncmp(b+i,"REDTEAM_HOSTENV",15))leak=1;if(!strncmp(b+i,"SYNAPSE_VAULT",13))leak=1;}
   printf("ENVLEAK worker_env_visible=%d\n",leak);}
  // --- namespace / escalation syscalls ---
  sc("unshare(NEWUSER)",SYS_unshare,CLONE_NEWUSER,0);
  sc("unshare(NEWNS)",SYS_unshare,CLONE_NEWNS,0);
  sc("setns",SYS_setns,0,0);
  sc("mount",SYS_mount,0,0);
  sc("ptrace",SYS_ptrace,0,0);
  sc("bpf",SYS_bpf,0,0);
  sc("keyctl",SYS_keyctl,0,0);
  sc("add_key",SYS_add_key,0,0);
  sc("userfaultfd",SYS_userfaultfd,0,0);
  sc("process_vm_readv",SYS_process_vm_readv,0,0);
  sc("io_uring_setup",SYS_io_uring_setup,0,0);
  sc("pivot_root",SYS_pivot_root,0,0);
  // chroot is a syscall too
  #ifdef SYS_chroot
  sc("chroot",SYS_chroot,(long)"/",0);
  #endif
  // --- clone(CLONE_NEWUSER): seccomp allows clone; can we make a nested userns? ---
  {long rc=syscall(SYS_clone,(long)(CLONE_NEWUSER|SIGCHLD),0,0,0,0);
   if(rc==0){_exit(42);} // child
   if(rc>0){int st;waitpid(rc,&st,0);printf("SYS  clone(NEWUSER)             rc=%ld errno=0 NESTED_USERNS_CREATED\n",rc);}
   else printf("SYS  clone(NEWUSER)             rc=%ld errno=%d\n",rc,errno);}
  // --- raw sockets ---
  sock("AF_PACKET/SOCK_RAW",AF_PACKET,SOCK_RAW,0);
  sock("AF_INET/SOCK_RAW",AF_INET,SOCK_RAW,IPPROTO_RAW);
  // --- egress: out-of-scope + metadata + ipv6 + in-scope ---
  tcp("metadata 169.254.169.254","169.254.169.254",80);
  tcp("out-of-scope 8.8.8.8","8.8.8.8",53);
  tcp("ipv6 cloudflare","2606:4700:4700::1111",80);
  tcp("in-scope 1.1.1.1","1.1.1.1",80);
  return 0;
}
`

func buildRedteam(t *testing.T) string {
	for _, b := range []string{"bwrap", "gcc"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not installed", b)
		}
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "rt.c"), []byte(redteamC), 0o644)
	bin := filepath.Join(dir, "rt")
	if out, err := exec.Command("gcc", "-O0", "-w", "-o", bin, filepath.Join(dir, "rt.c")).CombinedOutput(); err != nil {
		t.Fatalf("compile redteam probe: %v\n%s", err, out)
	}
	return bin
}

func TestRedTeamIsolated(t *testing.T) {
	requireSandboxIntegration(t)
	bin := buildRedteam(t)
	// Plant a host secret + a worker-env canary, then run ISOLATED (no egress).
	_ = os.MkdirAll("/root/.ssh", 0o700)
	_ = os.WriteFile("/root/.ssh/redteam_canary", []byte("CANARY_PRIVATE_KEY_DEADBEEF"), 0o600)
	defer os.Remove("/root/.ssh/redteam_canary")
	os.Setenv("REDTEAM_HOSTENV", "leakme")
	os.Setenv("SYNAPSE_VAULT_MASTER_KEY", "0000000000000000000000000000000000000000000000000000000000000000")
	sb, err := sandbox.NewRunner(60*time.Second, 64<<20, 1<<30, 256)
	if err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	res, err := sb.Run(context.Background(), ports.ToolSpec{Name: bin, Workdir: filepath.Dir(bin)})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	t.Logf("\n========== RED-TEAM (ISOLATED) ==========\n%s\n=========================================", res.Stdout)
	if len(res.Stderr) > 0 {
		t.Logf("stderr: %s", res.Stderr)
	}
}

func TestRedTeamEgress(t *testing.T) {
	requireSandboxIntegration(t)
	bin := buildRedteam(t)
	sb, err := sandbox.NewRunner(60*time.Second, 64<<20, 1<<30, 256)
	if err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	app, err := egress.NewApplier()
	if err != nil {
		t.Skipf("egress unavailable: %v", err)
	}
	ctx := context.Background()
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	perr := app.Probe(pctx)
	cancel()
	if perr != nil {
		t.Skipf("egress not usable (need sudo/CAP_NET_ADMIN): %v", perr)
	}
	sb.SetEgress(app)
	// In scope: only 1.1.1.1. Everything else (metadata, 8.8.8.8, v6) must be dropped.
	policy := ports.EgressPolicy{Rules: []ports.EgressRule{{Allow: true, Net: netip.MustParsePrefix("1.1.1.1/32")}}}
	res, err := sb.Run(ctx, ports.ToolSpec{Name: bin, Workdir: filepath.Dir(bin), EgressPolicy: &policy})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	out := string(res.Stdout)
	t.Logf("\n========== RED-TEAM (EGRESS, allow 1.1.1.1 only) ==========\n%s\nconnect-log entries: %d\n===========================================================", out, len(res.ConnectLog))
	for _, c := range res.ConnectLog {
		t.Logf("  connlog: %s:%d allowed=%v", c.IP, c.Port, c.Allowed)
	}
	if strings.Contains(out, "CANARY_PRIVATE_KEY") {
		t.Error("HOST SECRET LEAKED")
	}
}
