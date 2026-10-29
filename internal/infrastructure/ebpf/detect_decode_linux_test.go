//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func mustBytes(t *testing.T, v any) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, v); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b.Bytes()
}

// TestDecodeUsesKernelOccurredAt is the D4 regression: a decoded event's At is derived from the KERNEL
// timestamp in the record (boot epoch + bpf_ktime_get_ns), not the userspace drain time.
func TestDecodeUsesKernelOccurredAt(t *testing.T) {
	epoch := time.Unix(1_700_000_000, 0).UTC() // wall-clock instant of kernel monotonic zero (boot)
	const ktime = uint64(5 * 1_000_000_000)    // event occurred 5s after boot
	want := epoch.Add(5 * time.Second)

	rec := rawExec{Ktime: ktime, Start: 42, Kind: 1, PID: 4242, UID: 0}
	copy(rec.Filename[:], "/usr/bin/curl")
	ev, ok := decodeExec("host-1", mustBytes(t, &rec), epoch)
	if !ok {
		t.Fatal("decodeExec failed")
	}
	if !ev.At.Equal(want) {
		t.Fatalf("At must be kernel-derived (epoch+ktime=%v), got %v", want, ev.At)
	}
	if ev.At.Equal(epoch) {
		t.Fatal("At must include the kernel offset, not just the epoch")
	}

	// The same discipline for every class.
	frec := rawFile{Ktime: ktime, PID: 1}
	copy(frec.Filename[:], "/etc/shadow")
	if fe, ok := decodeFile("h", mustBytes(t, &frec), epoch); !ok || !fe.At.Equal(want) {
		t.Fatalf("decodeFile At = %v, want %v (ok=%v)", fe.At, want, ok)
	}
	prec := rawPriv{Ktime: ktime, PID: 1, ToUID: 0}
	copy(prec.Kind[:], "setuid")
	if pe, ok := decodePriv("h", mustBytes(t, &prec), epoch); !ok || !pe.At.Equal(want) {
		t.Fatalf("decodePriv At = %v, want %v (ok=%v)", pe.At, want, ok)
	}
	nrec := rawNet{Ktime: ktime, PID: 1, DPort: 53, Proto: 17}
	if ne, ok := decodeNet("h", mustBytes(t, &nrec), epoch); !ok || !ne.At.Equal(want) {
		t.Fatalf("decodeNet At = %v, want %v (ok=%v)", ne.At, want, ok)
	}
}

// TestDecodeFallsBackWhenNoKernelTimestamp confirms fail-safe: a zero kernel timestamp or an uncaptured
// epoch stamps a real (recent, non-zero) time rather than a bogus near-zero instant.
func TestDecodeFallsBackWhenNoKernelTimestamp(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	// Zero ktime -> fallback to userspace now.
	ev, ok := decodeExec("h", mustBytes(t, &rawExec{PID: 1, Start: 1, Kind: 1}), time.Unix(1_700_000_000, 0).UTC())
	if !ok || ev.At.Before(before) {
		t.Fatalf("zero ktime must fall back to a recent time, got %v", ev.At)
	}
	// Zero epoch (clock read failed) -> fallback even with a real ktime.
	ev2, ok := decodeExec("h", mustBytes(t, &rawExec{Ktime: 5_000_000_000, PID: 1, Start: 1, Kind: 1}), time.Time{})
	if !ok || ev2.At.Before(before) {
		t.Fatalf("zero epoch must fall back to a recent time, got %v", ev2.At)
	}
}

// TestKernelOccurredAtHelper unit-tests the mapping directly.
func TestKernelOccurredAtHelper(t *testing.T) {
	epoch := time.Unix(1_700_000_000, 0).UTC()
	if got := kernelOccurredAt(epoch, 2_000_000_000); !got.Equal(epoch.Add(2 * time.Second)) {
		t.Fatalf("kernelOccurredAt = %v, want epoch+2s", got)
	}
	if kernelOccurredAt(epoch, 0).IsZero() {
		t.Fatal("zero ktime must not yield a zero time")
	}
	if kernelOccurredAt(time.Time{}, 5).IsZero() {
		t.Fatal("zero epoch must not yield a zero time")
	}
}

func TestDecodeProcessLifecycleIdentity(t *testing.T) {
	for _, tc := range []struct {
		kind  uint32
		want  string
		valid bool
	}{
		{1, "exec", true}, {2, "exit", true}, {0, "", false}, {3, "", false},
	} {
		raw := rawExec{Kind: tc.kind, PID: 123, Start: 987654321}
		event, ok := decodeExec("host", mustBytes(t, &raw), time.Now())
		if ok != tc.valid {
			t.Fatalf("kind %d: ok=%v", tc.kind, ok)
		}
		if ok && (event.Process.Kind != tc.want || event.Process.PID != 123 || event.Process.StartTimeNanos != raw.Start) {
			t.Fatalf("kind %d lost identity: %+v", tc.kind, event.Process)
		}
	}
	for _, raw := range []rawExec{{Kind: 1, PID: 0, Start: 1}, {Kind: 2, PID: 123}} {
		if _, ok := decodeExec("host", mustBytes(t, &raw), time.Now()); ok {
			t.Fatalf("accepted zero identity: %+v", raw)
		}
	}
}
