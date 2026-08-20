package spool

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	frameMagic      uint32 = 0x53594e57 // SYNW
	frameVersion    uint16 = 1
	frameHeaderSize        = 48
	frameFlagNoShed uint16 = 1 << 0
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

type frameHeader struct {
	Magic      uint32
	Version    uint16
	HeaderSize uint16
	BodySize   uint32
	Checksum   uint32
	Priority   uint8
	Kind       uint8
	Flags      uint16
	Epoch      uint64
	Sequence   uint64
	ObservedNS int64
	MetaSize   uint32
}

type recordMeta struct {
	EventID       shared.ID            `json:"event_id"`
	EventClass    detection.Class      `json:"event_class,omitempty"`
	ContentType   string               `json:"content_type"`
	Session       fleetagent.SessionID `json:"session"`
	Boot          fleetagent.BootID    `json:"boot"`
	EnqueuedAt    time.Time            `json:"enqueued_at"`
	SchemaVersion int                  `json:"schema_version"`
}

func recordKindCode(kind ports.SpoolRecordKind) (uint8, bool) {
	switch kind {
	case ports.SpoolRecordTelemetry:
		return 1, true
	case ports.SpoolRecordDetection:
		return 2, true
	case ports.SpoolRecordCoverage:
		return 3, true
	case ports.SpoolRecordSensorState:
		return 4, true
	case ports.SpoolRecordResponseVerification:
		return 5, true
	default:
		return 0, false
	}
}

func recordKindFromCode(code uint8) (ports.SpoolRecordKind, bool) {
	switch code {
	case 1:
		return ports.SpoolRecordTelemetry, true
	case 2:
		return ports.SpoolRecordDetection, true
	case 3:
		return ports.SpoolRecordCoverage, true
	case 4:
		return ports.SpoolRecordSensorState, true
	case 5:
		return ports.SpoolRecordResponseVerification, true
	default:
		return "", false
	}
}

func encodeFrame(item ports.SpoolItem, position fleetagent.StreamPosition, enqueuedAt time.Time) ([]byte, error) {
	kind, ok := recordKindCode(item.Kind)
	if !ok {
		return nil, fmt.Errorf("encode WAL frame: unknown kind %q", item.Kind)
	}
	meta, err := json.Marshal(recordMeta{
		EventID: item.EventID, EventClass: item.EventClass, ContentType: item.ContentType,
		Session: position.Session, Boot: position.Boot, EnqueuedAt: enqueuedAt.UTC(),
		SchemaVersion: item.SchemaVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("encode WAL metadata: %w", err)
	}
	if len(meta) > int(maxFrameMetadataBytes) {
		return nil, fmt.Errorf("%w: encoded WAL metadata is %d bytes, maximum is %d", shared.ErrValidation, len(meta), maxFrameMetadataBytes)
	}
	bodySize := len(meta) + len(item.Payload)
	if bodySize > int(^uint32(0)) {
		return nil, errors.New("encode WAL frame: body exceeds format limit")
	}
	flags := uint16(0)
	if item.MustNotShed {
		flags |= frameFlagNoShed
	}
	header := frameHeader{
		Magic: frameMagic, Version: frameVersion, HeaderSize: frameHeaderSize,
		BodySize: uint32(bodySize), Priority: uint8(position.Priority), Kind: kind,
		Flags: flags, Epoch: position.Epoch, Sequence: position.Sequence,
		ObservedNS: item.ObservedAt.UTC().UnixNano(), MetaSize: uint32(len(meta)),
	}
	frame := make([]byte, frameHeaderSize+bodySize)
	marshalHeader(frame[:frameHeaderSize], header)
	copy(frame[frameHeaderSize:], meta)
	copy(frame[frameHeaderSize+len(meta):], item.Payload)
	header.Checksum = checksumFrame(frame)
	marshalHeader(frame[:frameHeaderSize], header)
	return frame, nil
}

func decodeFrame(frame []byte) (ports.SpoolRecord, frameHeader, error) {
	if len(frame) < frameHeaderSize {
		return ports.SpoolRecord{}, frameHeader{}, io.ErrUnexpectedEOF
	}
	header := unmarshalHeader(frame[:frameHeaderSize])
	if err := validateHeader(header); err != nil {
		return ports.SpoolRecord{}, header, err
	}
	want := frameHeaderSize + int(header.BodySize)
	if len(frame) != want {
		return ports.SpoolRecord{}, header, fmt.Errorf("WAL frame length %d, want %d: %w", len(frame), want, io.ErrUnexpectedEOF)
	}
	if checksumFrame(frame) != header.Checksum {
		return ports.SpoolRecord{}, header, errors.New("WAL frame checksum mismatch")
	}
	if header.MetaSize > header.BodySize {
		return ports.SpoolRecord{}, header, errors.New("WAL metadata exceeds frame body")
	}
	var meta recordMeta
	if err := json.Unmarshal(frame[frameHeaderSize:frameHeaderSize+int(header.MetaSize)], &meta); err != nil {
		return ports.SpoolRecord{}, header, fmt.Errorf("decode WAL metadata: %w", err)
	}
	kind, ok := recordKindFromCode(header.Kind)
	if !ok {
		return ports.SpoolRecord{}, header, fmt.Errorf("unknown WAL record kind %d", header.Kind)
	}
	record := ports.SpoolRecord{
		Kind: kind,
		Position: fleetagent.StreamPosition{
			Priority: fleetagent.DeliveryPriority(header.Priority), Epoch: header.Epoch,
			Sequence: header.Sequence, Session: meta.Session, Boot: meta.Boot,
		},
		EventID: meta.EventID, EventClass: meta.EventClass, ContentType: meta.ContentType,
		Payload:    append([]byte(nil), frame[frameHeaderSize+int(header.MetaSize):]...),
		ObservedAt: time.Unix(0, header.ObservedNS).UTC(), EnqueuedAt: meta.EnqueuedAt.UTC(),
		MustNotShed: header.Flags&frameFlagNoShed != 0, SchemaVersion: meta.SchemaVersion,
	}
	if err := record.Validate(); err != nil {
		return ports.SpoolRecord{}, header, fmt.Errorf("validate WAL record: %w", err)
	}
	return record, header, nil
}

func validateHeader(h frameHeader) error {
	if h.Magic != frameMagic {
		return errors.New("WAL frame magic mismatch")
	}
	if h.Version != frameVersion || h.HeaderSize != frameHeaderSize {
		return fmt.Errorf("unsupported WAL frame version/header %d/%d", h.Version, h.HeaderSize)
	}
	if !fleetagent.DeliveryPriority(h.Priority).Valid() {
		return fmt.Errorf("invalid WAL priority %d", h.Priority)
	}
	if _, ok := recordKindFromCode(h.Kind); !ok {
		return fmt.Errorf("invalid WAL kind %d", h.Kind)
	}
	if h.Epoch == 0 || h.Sequence == 0 {
		return errors.New("invalid zero WAL coordinate")
	}
	if h.BodySize == 0 || h.MetaSize == 0 || h.MetaSize > h.BodySize {
		return errors.New("invalid WAL body or metadata size")
	}
	return nil
}

func marshalHeader(dst []byte, h frameHeader) {
	binary.LittleEndian.PutUint32(dst[0:4], h.Magic)
	binary.LittleEndian.PutUint16(dst[4:6], h.Version)
	binary.LittleEndian.PutUint16(dst[6:8], h.HeaderSize)
	binary.LittleEndian.PutUint32(dst[8:12], h.BodySize)
	binary.LittleEndian.PutUint32(dst[12:16], h.Checksum)
	dst[16], dst[17] = h.Priority, h.Kind
	binary.LittleEndian.PutUint16(dst[18:20], h.Flags)
	binary.LittleEndian.PutUint64(dst[20:28], h.Epoch)
	binary.LittleEndian.PutUint64(dst[28:36], h.Sequence)
	binary.LittleEndian.PutUint64(dst[36:44], uint64(h.ObservedNS))
	binary.LittleEndian.PutUint32(dst[44:48], h.MetaSize)
}

func unmarshalHeader(src []byte) frameHeader {
	return frameHeader{
		Magic: binary.LittleEndian.Uint32(src[0:4]), Version: binary.LittleEndian.Uint16(src[4:6]),
		HeaderSize: binary.LittleEndian.Uint16(src[6:8]), BodySize: binary.LittleEndian.Uint32(src[8:12]),
		Checksum: binary.LittleEndian.Uint32(src[12:16]), Priority: src[16], Kind: src[17],
		Flags: binary.LittleEndian.Uint16(src[18:20]), Epoch: binary.LittleEndian.Uint64(src[20:28]),
		Sequence: binary.LittleEndian.Uint64(src[28:36]), ObservedNS: int64(binary.LittleEndian.Uint64(src[36:44])),
		MetaSize: binary.LittleEndian.Uint32(src[44:48]),
	}
}

func checksumFrame(frame []byte) uint32 {
	hasher := crc32.New(castagnoli)
	_, _ = hasher.Write(frame[:12])
	_, _ = hasher.Write([]byte{0, 0, 0, 0})
	_, _ = hasher.Write(frame[16:])
	return hasher.Sum32()
}
