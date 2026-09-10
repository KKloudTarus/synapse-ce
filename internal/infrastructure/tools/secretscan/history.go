package secretscan

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Git-history secret scanning. A secret committed and later removed is gone from the working tree but lives
// forever in the repository's object database, where an attacker who clones the repo can recover it. HEAD-only
// scanning (ScanFiles) misses these, so this walks every blob reachable from all refs and scans each unique
// one, the way gitleaks and trufflehog scan history. It shells to git argv-only (no shell, never concatenating
// a ref into a command), reads only the object database, and is bounded: a blob is scanned once (deduped by
// its immutable object id), the walk stops at object/finding caps, and each blob obeys the same size cap as a
// working-tree file. Secrets are redacted before they leave the package, exactly as the working-tree scan does.

const (
	maxHistoryObjects = 500_000 // (sha, path) pairs read from rev-list before the walk stops (a huge repo cap)
	maxHistoryBlobs   = 200_000 // unique blobs actually fetched + scanned (bounds cat-file work)
	maxHistoryCommits = 500_000 // commits walked by the introduction attribution log before it stops
	maxHistoryPathLen = 1024    // clip a stored blob path (a real path fits; bounds pathByBlob memory)
	maxGitStderr      = 4096    // cap captured git stderr so a noisy/hostile repo cannot exhaust memory
	gitBinary         = "git"
)

var _ ports.SecretHistoryScanner = (*Scanner)(nil)

// cappedBuffer captures at most cap bytes of a process's stderr, reporting a full write so the child never
// sees a short-write error. It bounds memory when a hostile repo makes git emit large diagnostics.
type cappedBuffer struct {
	buf bytes.Buffer
	cap int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if rem := c.cap - c.buf.Len(); rem > 0 {
		if len(p) > rem {
			c.buf.Write(p[:rem])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return c.buf.String() }

// ScanHistory scans every blob reachable from all refs in the git repository at repoDir for secrets, returning
// redacted findings attributed to a path the blob was stored under. repoDir must be a git repository; a
// non-repository or a git failure returns an error (the caller decides whether that is fatal). A blob whose
// content also appears in the working tree is deduped against it by the same content key, so an unchanged
// committed secret is not double-reported. Best-effort per blob: an unreadable or oversized blob is skipped.
func (s *Scanner) ScanHistory(ctx context.Context, repoDir string) (ports.SecretScanReport, error) {
	var report ports.SecretScanReport
	if err := ctx.Err(); err != nil {
		return report, fmt.Errorf("secret history scan: %w", err)
	}
	if strings.TrimSpace(repoDir) == "" {
		return report, fmt.Errorf("secret history scan: empty repository path")
	}
	pathByBlob, err := gitBlobObjects(ctx, repoDir)
	if err != nil {
		return report, err
	}
	// Attribute each blob to the commit that first introduced it (first-introducing commit + author + date).
	// Best-effort: a plain git-log failure yields no attribution (Commit/Author/FirstSeen stay empty, never
	// fabricated) rather than failing the scan; a context cancellation IS fatal.
	intro, ierr := gitBlobIntroductions(ctx, repoDir, pathByBlob)
	if ierr != nil && ctx.Err() != nil {
		return report, ierr
	}
	// Scan oldest-introduced blobs first so the (rule,path,line) dedup keeps the EARLIEST occurrence of a
	// secret, and stamp each finding with that blob's introducing commit.
	order := orderBlobsByIntroduction(pathByBlob, intro)
	seen := map[string]bool{} // (rule,path,line) dedup: the same secret across historical blobs collapses to one
	err = gitCatBlobs(ctx, repoDir, order, pathByBlob, func(sha, path string, data []byte) {
		if len(report.Findings) >= maxFindings {
			report.Truncated = true
			return
		}
		if isBinary(data) {
			return
		}
		start := len(report.Findings)
		if s.scanContent(path, data, seen, &report.Findings, maxFindings) {
			report.Truncated = true
		}
		bi, attributed := intro[sha]
		for i := start; i < len(report.Findings); i++ {
			report.Findings[i].FromHistory = true // every history hit keys distinctly from a working-tree hit
			if attributed {
				report.Findings[i].Commit = bi.commit
				report.Findings[i].Author = bi.author
				report.Findings[i].FirstSeen = bi.date
			}
		}
	})
	if err != nil {
		return report, err
	}
	return report, nil
}

// blobIntro is the commit that first introduced a blob into history: its hash, author name, and author date,
// plus seq, the 1-based chronological ordinal of that commit in the --reverse walk. seq gives a total oldest-
// first order even when several commits share an author-date second (RFC 3339 has only second precision), so
// it, not the date string, is what orders the scan.
type blobIntro struct {
	commit string
	author string
	date   string
	seq    int
}

// orderBlobsByIntroduction returns the blob object ids ordered oldest-introduced first (unattributed blobs
// last), with a stable sha tie-break, so the (rule,path,line) dedup in ScanHistory attributes a secret to its
// earliest occurrence.
func orderBlobsByIntroduction(pathByBlob map[string]string, intro map[string]blobIntro) []string {
	order := make([]string, 0, len(pathByBlob))
	for sha := range pathByBlob {
		order = append(order, sha)
	}
	sort.Slice(order, func(i, j int) bool {
		si, sj := introSeq(intro, order[i]), introSeq(intro, order[j])
		if si != sj {
			return si < sj
		}
		return order[i] < order[j]
	})
	return order
}

// introSeq returns a blob's introduction ordinal, or a sentinel that sorts after every attributed blob so an
// unattributed blob (introduced by a merge git log did not diff, or beyond the walk cap) scans last.
func introSeq(intro map[string]blobIntro, sha string) int {
	if bi, ok := intro[sha]; ok {
		return bi.seq
	}
	return int(^uint(0) >> 1) // math.MaxInt without importing math
}

// gitBlobIntroductions maps each blob object id in wanted to the commit that FIRST introduced it. It runs
// `git log --all --topo-order --reverse --raw`: --topo-order --reverse walks ancestors before descendants
// (parent-before-child even when author dates are skewed across refs), so the first commit adding a blob id is
// its true earliest introducer; --no-renames stops a rename from masking the add; --no-abbrev yields full ids
// that match cat-file. Only ids present in wanted (the capped set of blobs that will actually be scanned) are
// recorded, so the map is bounded by len(wanted) and non-blob ids (gitlinks, trees) never enter it. The custom
// format is NUL-prefixed so a header line is unambiguous against the ':'-prefixed raw diff lines. Read-only.
func gitBlobIntroductions(ctx context.Context, repoDir string, wanted map[string]string) (map[string]blobIntro, error) {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(cctx, gitBinary, "-C", repoDir, "log", "--all", "--topo-order", "--reverse",
		"--no-renames", "--no-abbrev", "--format=%x00%H%x1f%an%x1f%aI", "--raw")
	stderr := &cappedBuffer{cap: maxGitStderr}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git log stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start git log %q: %w", repoDir, err)
	}
	intro := make(map[string]blobIntro)
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var cur blobIntro
	commits := 0
	capped := false
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if line[0] == 0x00 { // commit header: "\x00<hash>\x1f<author>\x1f<date>"
			// Stop once every wanted blob is attributed, or the commit cap is hit.
			if commits >= maxHistoryCommits || len(intro) >= len(wanted) {
				capped = true
				break
			}
			commits++
			parts := strings.SplitN(line[1:], "\x1f", 3)
			if len(parts) == 3 {
				cur = blobIntro{commit: parts[0], author: parts[1], date: parts[2], seq: commits}
			} else {
				cur = blobIntro{seq: commits}
			}
			continue
		}
		if line[0] != ':' { // raw diff lines begin with ':'; ignore anything else (e.g. a stray blank)
			continue
		}
		// ":<srcmode> <dstmode> <srcsha> <dstsha> <status>\t<path>".
		left, _, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		fields := strings.Fields(left)
		if len(fields) < 5 || cur.commit == "" {
			continue
		}
		dstMode, srcSha, dstSha, status := fields[1], fields[2], fields[3], fields[4]
		if !isBlobMode(dstMode) { // skip gitlinks (160000) and trees; only a regular/exec/symlink blob is scanned
			continue
		}
		if status == "" || (status[0] != 'A' && status[0] != 'M' && status[0] != 'T') {
			continue
		}
		if dstSha == srcSha { // a mode-only change re-uses the same blob id; it introduces no new content
			continue
		}
		if !isHexSHA(dstSha) || isZeroSHA(dstSha) {
			continue
		}
		if _, want := wanted[dstSha]; !want { // only blobs that will actually be scanned
			continue
		}
		if _, exists := intro[dstSha]; !exists { // first (oldest, from --topo-order --reverse) commit wins
			intro[dstSha] = cur
		}
	}
	scanErr := sc.Err()
	if capped || scanErr != nil {
		cancel() // stop git early on a cap or a scanner failure so it cannot keep producing unbounded output
	}
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if scanErr != nil {
		return intro, fmt.Errorf("read git log output: %w", scanErr)
	}
	if ctx.Err() != nil {
		return intro, fmt.Errorf("secret history scan: %w", ctx.Err())
	}
	if !capped && waitErr != nil {
		return intro, fmt.Errorf("git log %q: %w: %s", repoDir, waitErr, truncate(stderr.String(), 200))
	}
	return intro, nil
}

// isBlobMode reports whether a git raw-diff mode is a file blob (regular, executable, or symlink), excluding
// gitlinks (160000) and trees, so only ids that can carry a secret and will be scanned are attributed.
func isBlobMode(mode string) bool {
	switch mode {
	case "100644", "100755", "120000":
		return true
	default:
		return false
	}
}

// isZeroSHA reports whether s is an all-zero git object id (the "no object" side of an add/delete raw line).
func isZeroSHA(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}

// gitBlobObjects lists every (blob object id -> a path it was stored under) reachable from all refs, via
// `git rev-list --objects --all`. rev-list prints "<sha>" for a commit and "<sha> <path>" for a tree or blob;
// only the path-bearing entries are candidate blobs (trees are filtered out by cat-file's type). The first
// path seen for a blob is kept (a blob can appear under several paths across history). The walk is capped.
func gitBlobObjects(ctx context.Context, repoDir string) (map[string]string, error) {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(cctx, gitBinary, "-C", repoDir, "rev-list", "--objects", "--all")
	stderr := &cappedBuffer{cap: maxGitStderr}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git rev-list stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start git rev-list %q: %w", repoDir, err)
	}
	// Stream stdout line by line (never buffer the whole object list, which is unbounded on a hostile repo)
	// and stop at the cap by cancelling the process.
	pathByBlob := make(map[string]string)
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	objects := 0
	capped := false
	for sc.Scan() {
		if objects >= maxHistoryObjects || len(pathByBlob) >= maxHistoryBlobs {
			capped = true
			break
		}
		objects++
		sha, path, ok := strings.Cut(sc.Text(), " ")
		if !ok || path == "" || !isHexSHA(sha) { // a bare sha is a commit, not a blob
			continue
		}
		if _, dup := pathByBlob[sha]; !dup {
			if len(path) > maxHistoryPathLen {
				path = path[:maxHistoryPathLen]
			}
			// Clone so the map entry does not pin the whole (up to 1 MiB) rev-list line's backing array.
			pathByBlob[strings.Clone(sha)] = strings.Clone(path)
		}
	}
	scanErr := sc.Err()
	if capped {
		cancel() // stop git early; a normal completion is left to exit on its own so Wait reports its real status
	}
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if scanErr != nil {
		return nil, fmt.Errorf("read git rev-list output: %w", scanErr)
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("secret history scan: %w", ctx.Err())
	}
	// A cap-triggered cancel makes git exit non-zero (killed); that is expected, so only a genuine failure
	// (e.g. not a git repository) with output we did not truncate is surfaced.
	if !capped && waitErr != nil {
		return nil, fmt.Errorf("git rev-list %q: %w: %s", repoDir, waitErr, truncate(stderr.String(), 200))
	}
	return pathByBlob, nil
}

// gitCatBlobs streams the content of each object id through `git cat-file --batch` (one process, ids on
// stdin) and invokes fn(path, content) for every object that is a blob within the size cap. Non-blob objects
// (trees) and oversized blobs are skipped. The batch protocol is: for each id, a header line
// "<sha> <type> <size>" followed by <size> raw bytes and a trailing newline; a missing id yields "<sha>
// missing". Parsing is bounded and never blocks: stdin is closed after the id list is written.
func gitCatBlobs(ctx context.Context, repoDir string, order []string, pathByBlob map[string]string, fn func(sha, path string, data []byte)) error {
	if len(order) == 0 {
		return nil
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel() // on any return, kill cat-file so the stdin-writer goroutine cannot block forever
	cmd := exec.CommandContext(cctx, gitBinary, "-C", repoDir, "cat-file", "--batch")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("git cat-file stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("git cat-file stdout: %w", err)
	}
	stderr := &cappedBuffer{cap: maxGitStderr}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start git cat-file: %w", err)
	}
	// Write the id list, then close stdin so cat-file finishes; run in a goroutine so a large id list cannot
	// deadlock against unread stdout.
	writeErr := make(chan error, 1)
	go func() {
		w := bufio.NewWriter(stdin)
		var werr error
		for _, sha := range order {
			if _, e := w.WriteString(sha + "\n"); e != nil {
				werr = e
				break
			}
		}
		if werr == nil {
			werr = w.Flush()
		}
		_ = stdin.Close()
		writeErr <- werr
	}()

	r := bufio.NewReader(stdout)
	parseErr := parseCatFileBatch(cctx, r, pathByBlob, fn)
	if parseErr != nil {
		cancel() // stop cat-file NOW so a still-writing stdin goroutine unblocks (its Write fails on the closed pipe)
	}
	// Drain any remaining stdout so cat-file can finish, then reap the process and the writer.
	_, _ = io.Copy(io.Discard, r)
	waitErr := cmd.Wait()
	<-writeErr // the writer's error is subsumed by parse/wait below
	if parseErr != nil {
		return parseErr
	}
	if ctx.Err() != nil {
		return fmt.Errorf("secret history scan: %w", ctx.Err())
	}
	if waitErr != nil {
		return fmt.Errorf("git cat-file %q: %w: %s", repoDir, waitErr, truncate(stderr.String(), 200))
	}
	return nil
}

// parseCatFileBatch reads the cat-file --batch stream, calling fn for each blob within the size cap.
func parseCatFileBatch(ctx context.Context, r *bufio.Reader, pathByBlob map[string]string, fn func(sha, path string, data []byte)) error {
	blobs := 0
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("secret history scan: %w", err)
		}
		if blobs >= maxHistoryBlobs {
			return nil
		}
		header, err := r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				if header == "" {
					return nil // clean end of stream: every record consumed
				}
				return fmt.Errorf("truncated git cat-file header %q", header) // partial header: corrupt/truncated output
			}
			return fmt.Errorf("read git cat-file header: %w", err)
		}
		fields := strings.Fields(strings.TrimRight(header, "\n"))
		if len(fields) == 2 && fields[1] == "missing" {
			continue // an id git no longer has (shouldn't happen from rev-list, but tolerate)
		}
		if len(fields) != 3 {
			return fmt.Errorf("unexpected git cat-file header %q", strings.TrimRight(header, "\n"))
		}
		sha, typ, sizeStr := fields[0], fields[1], fields[2]
		size, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil || size < 0 {
			return fmt.Errorf("invalid git cat-file size %q", sizeStr)
		}
		if typ != "blob" || size > maxFileBytes {
			if err := discard(r, size); err != nil { // skip the object content...
				return err
			}
			if err := readTerminator(r, sha); err != nil { // ...then its newline terminator (no size+1 overflow)
				return err
			}
			continue
		}
		blobs++
		data := make([]byte, size)
		if _, err := io.ReadFull(r, data); err != nil {
			return fmt.Errorf("read git cat-file blob %s: %w", sha, err)
		}
		if err := readTerminator(r, sha); err != nil {
			return err
		}
		fn(sha, pathByBlob[sha], data)
	}
}

// readTerminator consumes the single-byte record terminator git writes after each cat-file object and
// requires it to be a newline; anything else (or EOF) means corrupt/truncated output.
func readTerminator(r *bufio.Reader, sha string) error {
	term, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("read git cat-file terminator for %s: %w", sha, err)
	}
	if term != '\n' {
		return fmt.Errorf("git cat-file object %s not newline-terminated", sha)
	}
	return nil
}

// discard skips exactly n bytes from r, returning an error if the stream ends first (a truncated record).
func discard(r *bufio.Reader, n int64) error {
	for n > 0 {
		step := n
		if step > 1<<20 {
			step = 1 << 20
		}
		skipped, err := r.Discard(int(step))
		n -= int64(skipped)
		if err != nil {
			// EOF before the whole object was skipped means the stream was truncated mid-record; that is a
			// corrupt/incomplete scan, not a clean end, so surface it rather than silently continuing.
			return fmt.Errorf("skip git cat-file object: %w", err)
		}
	}
	return nil
}

// truncate caps a git stderr snippet for an error message (git diagnostics can be long and echo repo paths).
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// isHexSHA reports whether s is a 40- or 64-hex-character git object id (SHA-1 or SHA-256).
func isHexSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
