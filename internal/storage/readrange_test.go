package storage

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestReadRange(t *testing.T) {
	const data = "0123456789"
	size := int64(len(data))

	tests := []struct {
		name           string
		offset, length int64
		want           string
	}{
		{"whole", 0, size, "0123456789"},
		{"whole via length -1", 0, -1, "0123456789"},
		{"prefix", 0, 3, "012"},
		{"middle", 3, 4, "3456"},
		{"suffix last 3", size - 3, 3, "789"},
		{"length past end clamps", size - 3, 100, "789"},
		{"open ended from offset", 4, -1, "456789"},
		{"offset at end", size, 5, ""},
		{"offset past end", size + 5, 5, ""},
		{"zero length", 2, 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			n, err := ReadRange(&buf, strings.NewReader(data), size, tt.offset, tt.length)
			if err != nil {
				t.Fatalf("ReadRange(off=%d, len=%d): %v", tt.offset, tt.length, err)
			}
			if got := buf.String(); got != tt.want || n != int64(len(tt.want)) {
				t.Fatalf("ReadRange(off=%d, len=%d) = %q (n=%d), want %q",
					tt.offset, tt.length, got, n, tt.want)
			}
		})
	}
}

func TestReadRangeEmptyObject(t *testing.T) {
	var buf bytes.Buffer
	n, err := ReadRange(&buf, strings.NewReader(""), 0, 0, 10)
	if err != nil {
		t.Fatalf("ReadRange: %v", err)
	}
	if n != 0 || buf.Len() != 0 {
		t.Fatalf("empty object: n=%d bytes=%q, want 0 bytes", n, buf.String())
	}
}

func TestReadRangeNegativeOffset(t *testing.T) {
	var buf bytes.Buffer
	_, err := ReadRange(&buf, strings.NewReader("abc"), 3, -1, 2)
	if !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("negative offset: error = %v, want ErrInvalidRange", err)
	}
}
