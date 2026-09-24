package gobinreach

import "io"

const maxBuildInfoReadBytes = 32 << 20

// budgetReaderAt prevents build-info parsing from reading an unbounded data segment or module string.
type budgetReaderAt struct {
	source    io.ReaderAt
	remaining int64
}

func (reader *budgetReaderAt) ReadAt(data []byte, offset int64) (int, error) {
	if int64(len(data)) > reader.remaining {
		return 0, io.ErrUnexpectedEOF
	}
	read, err := reader.source.ReadAt(data, offset)
	reader.remaining -= int64(read)
	return read, err
}
