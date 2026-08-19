package telemetry

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Stable entity identity for the raw-telemetry tier (A1, fixes D4). A raw PID is NOT an identity: the
// kernel reuses a PID the moment a process dies, so two unrelated processes can share one PID within a
// boot, and the same PID means different things across a reboot. These helpers derive a content-addressed
// id that is stable for the life of one process and distinct across PID reuse and reboots.
//
// Every id is a domain-separated sha256 over a LENGTH-PREFIXED encoding of its parts (never a delimiter
// join): a naive `a + sep + b` collides when a field can contain the separator (e.g. a path or a host id
// with an embedded NUL), which is exactly the class of bug the columnar-key work removed. Length-prefixing
// makes the encoding unambiguous regardless of field content.

// hashFields returns the hex sha256 of a domain-separated, length-prefixed encoding of parts. The domain
// string is written first (and length-prefixed) so an id computed for one purpose can never equal an id
// for another purpose, even with identical parts.
func hashFields(domain string, parts ...string) string {
	h := sha256.New()
	writeField(h, domain)
	for _, p := range parts {
		writeField(h, p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeField(h io.Writer, s string) {
	var lp [8]byte
	binary.BigEndian.PutUint64(lp[:], uint64(len(s)))
	_, _ = h.Write(lp[:])
	_, _ = io.WriteString(h, s)
}

func uint64Str(v uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return string(b[:])
}

// ProcessEntityID derives the stable identity of a process from the tuple that actually pins it:
// (AssetID, BootID, PID, StartTimeNanos). StartTimeNanos is the kernel process start time — it is what
// makes a reused PID a DISTINCT entity; BootID makes the same (pid, start) on a different boot distinct.
// The id is prefixed "pe_" so it is self-describing in logs and evidence.
func ProcessEntityID(assetID, bootID shared.ID, pid int, startTimeNanos uint64) shared.ID {
	sum := hashFields("telemetry:process-entity:v1",
		assetID.String(), bootID.String(), uint64Str(uint64(int64(pid))), uint64Str(startTimeNanos))
	return shared.ID("pe_" + sum[:32])
}

// FileTargetID derives the identity of a file target from (path, device, inode, contentHash). Path alone
// is not identity — it is rebindable (rename/symlink/bind-mount) — so device+inode pin the concrete
// object and the optional contentHash pins its contents at observation time.
func FileTargetID(path string, device, inode uint64, contentHash string) shared.ID {
	sum := hashFields("telemetry:file-target:v1", path, uint64Str(device), uint64Str(inode), contentHash)
	return shared.ID("ft_" + sum[:32])
}

// ContainerTargetID derives the identity of a container target from
// (containerID, cgroupID, podUID, imageDigest). A bare container id or pod name is not durable identity
// across a restart; the combination pins the concrete running instance.
func ContainerTargetID(containerID string, cgroupID uint64, podUID, imageDigest string) shared.ID {
	sum := hashFields("telemetry:container-target:v1", containerID, uint64Str(cgroupID), podUID, imageDigest)
	return shared.ID("ct_" + sum[:32])
}
