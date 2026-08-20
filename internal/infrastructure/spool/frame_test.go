package spool

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestFrameRoundTripEveryRecordKind(t *testing.T) {
	kinds := []ports.SpoolRecordKind{
		ports.SpoolRecordTelemetry, ports.SpoolRecordDetection, ports.SpoolRecordCoverage,
		ports.SpoolRecordSensorState, ports.SpoolRecordResponseVerification,
	}
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			priority := fleetagent.PriorityP0
			if kind == ports.SpoolRecordTelemetry {
				priority = fleetagent.PriorityP3
			} else if kind == ports.SpoolRecordDetection {
				priority = fleetagent.PriorityP1
			}
			item := testItem(priority, "event-1", 32)
			item.Kind = kind
			if kind != ports.SpoolRecordTelemetry {
				item.EventClass = ""
			}
			position := fleetagent.StreamPosition{Priority: priority, Epoch: 7, Sequence: 99, Session: "session", Boot: "boot"}
			frame, err := encodeFrame(item, position, testNow)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			record, header, err := decodeFrame(frame)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if header.Checksum == 0 || header.BodySize == 0 || header.MetaSize == 0 {
				t.Fatalf("incomplete header: %#v", header)
			}
			if record.Kind != kind || record.Position != position || record.EventID != item.EventID || !bytes.Equal(record.Payload, item.Payload) {
				t.Fatalf("round trip mismatch: %#v", record)
			}
			item.Payload[0] ^= 0xff
			if bytes.Equal(record.Payload, item.Payload) {
				t.Fatal("decoded payload aliases caller memory")
			}
		})
	}
}

func TestFrameChecksumCoversHeaderAndPayload(t *testing.T) {
	item := testItem(fleetagent.PriorityP2, "checksum", 128)
	position := fleetagent.StreamPosition{Priority: fleetagent.PriorityP2, Epoch: 2, Sequence: 3, Session: "s", Boot: "b"}
	frame, err := encodeFrame(item, position, testNow)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		offset int
	}{
		{"coordinate", 28},
		{"timestamp", 36},
		{"metadata", frameHeaderSize + 2},
		{"payload", len(frame) - 1},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			corrupt := append([]byte(nil), frame...)
			corrupt[mutation.offset] ^= 0x40
			if _, _, err := decodeFrame(corrupt); err == nil {
				t.Fatal("corrupt frame decoded successfully")
			}
		})
	}
}

func TestDecodeFrameRejectsTruncationAndFormatBombs(t *testing.T) {
	item := testItem(fleetagent.PriorityP3, "bounded", 32)
	position := fleetagent.StreamPosition{Priority: fleetagent.PriorityP3, Epoch: 1, Sequence: 1, Session: "s", Boot: "b"}
	frame, err := encodeFrame(item, position, testNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 1, frameHeaderSize - 1, frameHeaderSize, len(frame) - 1} {
		_, _, err := decodeFrame(frame[:size])
		if err == nil {
			t.Errorf("truncated size %d decoded", size)
		}
		if size < frameHeaderSize && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("size %d error = %v, want unexpected EOF", size, err)
		}
	}
	bad := append([]byte(nil), frame...)
	binary.LittleEndian.PutUint32(bad[44:48], binary.LittleEndian.Uint32(bad[8:12])+1)
	if _, _, err := decodeFrame(bad); err == nil {
		t.Fatal("metadata larger than body accepted")
	}
}

func TestEncodeFrameRejectsMetadataOutsideReservedOverhead(t *testing.T) {
	item := testItem(fleetagent.PriorityP3, "bounded-meta", 32)
	item.ContentType = strings.Repeat("x", int(maxFrameMetadataBytes))
	position := fleetagent.StreamPosition{Priority: fleetagent.PriorityP3, Epoch: 1, Sequence: 1, Session: "s", Boot: "b"}
	if _, err := encodeFrame(item, position, testNow); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized metadata error = %v, want validation error", err)
	}
}

func TestRecordKindCodesAreStableAndBijective(t *testing.T) {
	for code := uint8(1); code <= 5; code++ {
		kind, ok := recordKindFromCode(code)
		if !ok {
			t.Fatalf("code %d missing", code)
		}
		back, ok := recordKindCode(kind)
		if !ok || back != code {
			t.Fatalf("code %d -> %q -> %d", code, kind, back)
		}
	}
	if _, ok := recordKindFromCode(0); ok {
		t.Fatal("zero kind code accepted")
	}
	if _, ok := recordKindCode("future"); ok {
		t.Fatal("unknown kind accepted")
	}
}

func FuzzDecodeFrameNeverPanics(f *testing.F) {
	item := testItem(fleetagent.PriorityP3, "fuzz", 64)
	position := fleetagent.StreamPosition{Priority: fleetagent.PriorityP3, Epoch: 1, Sequence: 1, Session: "s", Boot: "b"}
	valid, _ := encodeFrame(item, position, testNow)
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte("SYNW"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = decodeFrame(data)
	})
}
