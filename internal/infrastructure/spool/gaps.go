package spool

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	gapMagic      uint32 = 0x53594750 // SYGP
	gapHeaderSize        = 12
	maxGapBody           = 64 << 10
)

func openGapJournal(dir string) (*os.File, []ports.SpoolGap, int64, error) {
	path := filepath.Join(dir, "gaps.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("open gap journal: %w", err)
	}
	if err := securePath(path, 0o600); err != nil {
		_ = f.Close()
		return nil, nil, 0, fmt.Errorf("secure gap journal: %w", err)
	}
	gaps, validBytes, err := readGapJournal(f)
	if err != nil {
		_ = f.Close()
		return nil, nil, 0, err
	}
	stat, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, 0, err
	}
	if stat.Size() != validBytes {
		if err := f.Truncate(validBytes); err != nil {
			_ = f.Close()
			return nil, nil, 0, fmt.Errorf("truncate torn gap journal: %w", err)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return nil, nil, 0, fmt.Errorf("sync repaired gap journal: %w", err)
		}
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return nil, nil, 0, err
	}
	return f, gaps, validBytes, nil
}

func readGapJournal(f *os.File) ([]ports.SpoolGap, int64, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, 0, err
	}
	var gaps []ports.SpoolGap
	var offset int64
	header := make([]byte, gapHeaderSize)
	for {
		n, err := io.ReadFull(f, header)
		if errors.Is(err, io.EOF) {
			return gaps, offset, nil
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return gaps, offset, nil // a crash before Sync: safe to truncate
		}
		if err != nil {
			return nil, offset, fmt.Errorf("read gap journal header: %w", err)
		}
		if n != gapHeaderSize || binary.LittleEndian.Uint32(header[0:4]) != gapMagic {
			return nil, offset, fmt.Errorf("gap journal corruption at offset %d", offset)
		}
		length := binary.LittleEndian.Uint32(header[4:8])
		checksum := binary.LittleEndian.Uint32(header[8:12])
		if length == 0 || length > maxGapBody {
			return nil, offset, fmt.Errorf("invalid gap record length %d at offset %d", length, offset)
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(f, body); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return gaps, offset, nil
			}
			return nil, offset, fmt.Errorf("read gap journal body: %w", err)
		}
		if crc32.Checksum(body, castagnoli) != checksum {
			return nil, offset, fmt.Errorf("gap journal checksum mismatch at offset %d", offset)
		}
		var gap ports.SpoolGap
		if err := json.Unmarshal(body, &gap); err != nil {
			return nil, offset, fmt.Errorf("decode gap at offset %d: %w", offset, err)
		}
		if err := gap.Validate(); err != nil {
			return nil, offset, fmt.Errorf("validate gap at offset %d: %w", offset, err)
		}
		gaps = append(gaps, gap)
		offset += int64(gapHeaderSize) + int64(length)
	}
}

func (s *Spool) appendGapLocked(gap ports.SpoolGap) error {
	if err := gap.Validate(); err != nil {
		return err
	}
	body, err := json.Marshal(gap)
	if err != nil {
		return fmt.Errorf("encode spool gap: %w", err)
	}
	if len(body) > maxGapBody {
		return errors.New("encoded spool gap exceeds journal format limit")
	}
	frame := make([]byte, gapHeaderSize+len(body))
	binary.LittleEndian.PutUint32(frame[0:4], gapMagic)
	binary.LittleEndian.PutUint32(frame[4:8], uint32(len(body)))
	binary.LittleEndian.PutUint32(frame[8:12], crc32.Checksum(body, castagnoli))
	copy(frame[gapHeaderSize:], body)
	written, writeErr := s.gapFile.Write(frame)
	if writeErr != nil || written != len(frame) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		truncateErr := s.gapFile.Truncate(s.gapBytes)
		_, seekErr := s.gapFile.Seek(0, io.SeekEnd)
		return errors.Join(fmt.Errorf("append spool gap: %w", writeErr), truncateErr, seekErr)
	}
	started := s.cfg.Now()
	if err := s.gapFile.Sync(); err != nil {
		return fmt.Errorf("sync spool gap: %w", err)
	}
	s.observeSyncLocked(started)
	s.gaps = append(s.gaps, gap)
	s.gapBytes += int64(len(frame))
	return nil
}
