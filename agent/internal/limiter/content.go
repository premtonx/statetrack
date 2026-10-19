package limiter

import "bytes"

const (
	// MaxDiffFileSize is the largest file that is diffed line by line.
	MaxDiffFileSize = 1 << 20
	// BinarySniffLen is how many leading bytes are checked for NUL bytes.
	BinarySniffLen = 512
)

// ContentKind tells whether a file may be diffed as text.
type ContentKind int

const (
	ContentText     ContentKind = iota
	ContentBinary               // NUL byte within the first BinarySniffLen bytes
	ContentTooLarge             // larger than MaxDiffFileSize
)

func (k ContentKind) String() string {
	switch k {
	case ContentText:
		return "text"
	case ContentBinary:
		return "binary"
	case ContentTooLarge:
		return "too_large"
	}
	return "unknown"
}

// DetectContent classifies a file from its total size and leading bytes.
func DetectContent(size int64, head []byte) ContentKind {
	if size > MaxDiffFileSize {
		return ContentTooLarge
	}
	if len(head) > BinarySniffLen {
		head = head[:BinarySniffLen]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return ContentBinary
	}
	return ContentText
}
