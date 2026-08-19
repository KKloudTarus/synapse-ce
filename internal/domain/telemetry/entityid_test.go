package telemetry

import "testing"

func TestProcessEntityIDDeterministic(t *testing.T) {
	a := ProcessEntityID("asset-1", "boot-1", 1234, 999)
	b := ProcessEntityID("asset-1", "boot-1", 1234, 999)
	if a != b {
		t.Fatalf("same tuple must yield same id: %q != %q", a, b)
	}
	if a == "" || len(a) < 4 || a[:3] != "pe_" {
		t.Fatalf("id must be non-empty and prefixed pe_: %q", a)
	}
}

func TestProcessEntityIDPIDReuse(t *testing.T) {
	// Same PID, DIFFERENT start time = a reused PID after the first process died => a DISTINCT entity.
	first := ProcessEntityID("asset-1", "boot-1", 1234, 1000)
	reused := ProcessEntityID("asset-1", "boot-1", 1234, 2000)
	if first == reused {
		t.Fatalf("PID reuse with a new start time must produce a distinct id: both %q", first)
	}
}

func TestProcessEntityIDRebootDistinct(t *testing.T) {
	// Same (pid, start) on a different boot => distinct entity (start time is only monotonic within a boot).
	before := ProcessEntityID("asset-1", "boot-1", 1234, 1000)
	afterReboot := ProcessEntityID("asset-1", "boot-2", 1234, 1000)
	if before == afterReboot {
		t.Fatalf("a reboot (new BootID) must produce a distinct id: both %q", before)
	}
}

func TestProcessEntityIDAssetDistinct(t *testing.T) {
	h1 := ProcessEntityID("asset-1", "boot-1", 1234, 1000)
	h2 := ProcessEntityID("asset-2", "boot-1", 1234, 1000)
	if h1 == h2 {
		t.Fatalf("different assets must produce distinct ids: both %q", h1)
	}
}

// TestProcessEntityIDNoDelimiterCollision proves the length-prefixed encoding is unambiguous: two
// different field splittings that would collide under a naive `a + sep + b` join must NOT collide.
func TestProcessEntityIDNoDelimiterCollision(t *testing.T) {
	// asset "a" boot "bc" vs asset "ab" boot "c" — a delimiter join of the string fields could alias.
	x := ProcessEntityID("a", "bc", 1, 1)
	y := ProcessEntityID("ab", "c", 1, 1)
	if x == y {
		t.Fatalf("length-prefixing must prevent field-boundary collisions: both %q", x)
	}
}

func TestFileTargetIDDistinctness(t *testing.T) {
	// Same path, different inode (path rebound to a new object) => distinct target.
	a := FileTargetID("/etc/shadow", 66, 100, "")
	b := FileTargetID("/etc/shadow", 66, 200, "")
	if a == b {
		t.Fatalf("different inode must give a distinct file target id")
	}
	if a[:3] != "ft_" {
		t.Fatalf("file target id must be prefixed ft_: %q", a)
	}
	// Content hash participates: same path+dev+inode, different content => distinct.
	c := FileTargetID("/etc/shadow", 66, 100, "hashA")
	d := FileTargetID("/etc/shadow", 66, 100, "hashB")
	if c == d {
		t.Fatalf("different content hash must give a distinct file target id")
	}
}

func TestContainerTargetIDDistinctness(t *testing.T) {
	a := ContainerTargetID("cid-1", 42, "pod-uid-1", "sha256:img")
	b := ContainerTargetID("cid-1", 42, "pod-uid-1", "sha256:img")
	if a != b {
		t.Fatalf("same container tuple must be stable")
	}
	c := ContainerTargetID("cid-2", 42, "pod-uid-1", "sha256:img")
	if a == c {
		t.Fatalf("different container id must be distinct")
	}
	if a[:3] != "ct_" {
		t.Fatalf("container target id must be prefixed ct_: %q", a)
	}
}

// TestDistinctIDNamespaces confirms domain separation: the same raw parts hashed for different purposes
// never collide across id kinds.
func TestDistinctIDNamespaces(t *testing.T) {
	p := ProcessEntityID("x", "y", 0, 0)
	f := FileTargetID("x", 0, 0, "y")
	if string(p)[3:] == string(f)[3:] {
		t.Fatalf("process and file id hashes must be domain-separated")
	}
}
