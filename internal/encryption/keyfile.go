package encryption

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// ReadKeyFile reads an at-rest key file: the hex form of a KeySize-byte key,
// with surrounding whitespace allowed. Keys are handed over as files rather
// than flag or environment values so they stay out of process listings and
// environment dumps.
func ReadKeyFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("encryption: read key file: %w", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("%w: key file %s is not hex", ErrInvalidKey, path)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: key file %s holds %d bytes, want %d", ErrInvalidKey, path, len(key), KeySize)
	}

	return key, nil
}
