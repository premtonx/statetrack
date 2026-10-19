package diff

import (
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// MaxDecompressedSize bounds the output of Decompress to protect the server
// from decompression bombs in agent-supplied payloads.
const MaxDecompressedSize = 64 << 20

var (
	encOnce sync.Once
	enc     *zstd.Encoder
	encErr  error

	decOnce sync.Once
	dec     *zstd.Decoder
	decErr  error
)

func encoder() (*zstd.Encoder, error) {
	encOnce.Do(func() {
		enc, encErr = zstd.NewWriter(nil,
			zstd.WithEncoderLevel(zstd.SpeedDefault),
			zstd.WithEncoderConcurrency(1),
			zstd.WithWindowSize(1<<21),
			zstd.WithLowerEncoderMem(true),
		)
	})
	return enc, encErr
}

func decoder() (*zstd.Decoder, error) {
	decOnce.Do(func() {
		dec, decErr = zstd.NewReader(nil,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(MaxDecompressedSize),
			zstd.WithDecoderLowmem(true),
		)
	})
	return dec, decErr
}

// Compress returns data as a single Zstd frame. It is safe for concurrent use.
func Compress(data []byte) ([]byte, error) {
	e, err := encoder()
	if err != nil {
		return nil, fmt.Errorf("zstd encoder: %w", err)
	}
	return e.EncodeAll(data, make([]byte, 0, len(data)/2+64)), nil
}

// Decompress decodes a Zstd payload produced by Compress. It is safe for
// concurrent use and fails for outputs larger than MaxDecompressedSize.
func Decompress(data []byte) ([]byte, error) {
	d, err := decoder()
	if err != nil {
		return nil, fmt.Errorf("zstd decoder: %w", err)
	}
	out, err := d.DecodeAll(data, nil)
	if err != nil {
		return nil, fmt.Errorf("zstd decode: %w", err)
	}
	return out, nil
}

// CompressString is a convenience wrapper for compressing a unified diff.
func CompressString(s string) ([]byte, error) { return Compress([]byte(s)) }

// DecompressString is a convenience wrapper returning the payload as a string.
func DecompressString(data []byte) (string, error) {
	out, err := Decompress(data)
	return string(out), err
}
