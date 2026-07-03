package drs_test

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ddbj/humandbs-drs/internal/drs"
	"github.com/ddbj/humandbs-drs/internal/encryption"
)

// newAtRestFixture seals files (relative path -> plaintext) into at-rest
// envelopes under one dataset root and serves them with the matching provider.
// A small chunkSize makes multi-chunk objects cheap to build.
func newAtRestFixture(t *testing.T, chunkSize int, files map[string]string) *fixture {
	t.Helper()

	key := bytes.Repeat([]byte{0x42}, encryption.KeySize)
	enc, err := encryption.NewAtRest(key, chunkSize)
	if err != nil {
		t.Fatalf("NewAtRest: %v", err)
	}

	root := t.TempDir()
	for rel, content := range files {
		var envelope bytes.Buffer
		if err := enc.Encrypt(&envelope, strings.NewReader(content)); err != nil {
			t.Fatalf("Encrypt %s: %v", rel, err)
		}
		writeFile(t, filepath.Join(root, rel), envelope.String())
	}

	f := serveFixture(t, root, enc)
	t.Cleanup(f.close)

	return f
}

// TestAtRestObjectDescribesPlaintext pins that the DrsObject of an encrypted
// object carries the plaintext size and checksum — the values a client verifies
// its download against — not those of the envelope on disk.
func TestAtRestObjectDescribesPlaintext(t *testing.T) {
	const content = "controlled-access payload"
	f := newAtRestFixture(t, 8, map[string]string{"a.bin": content})
	id := f.ids[0]

	resp, err := http.Get(f.url("/objects/" + id))
	if err != nil {
		t.Fatalf("GET object: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var obj drs.Object
	decodeBody(t, resp, &obj)
	if obj.Size != int64(len(content)) {
		t.Errorf("size = %d, want plaintext %d", obj.Size, len(content))
	}
	if len(obj.Checksums) != 1 || obj.Checksums[0].Checksum != sha256hex(content) {
		t.Errorf("checksums = %+v, want plaintext sha-256 %s", obj.Checksums, sha256hex(content))
	}
}

// TestAtRestFullDownloadDecrypts pins the § 4.6 delivery guarantee: the client
// receives the plaintext of a multi-chunk envelope, sized and tagged in
// plaintext terms.
func TestAtRestFullDownloadDecrypts(t *testing.T) {
	const content = "chunked plaintext that spans several small chunks"
	f := newAtRestFixture(t, 8, map[string]string{"a.bin": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	res := f.get(t, id, tok, nil)
	if res.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.status)
	}
	if got := res.header.Get("Content-Length"); got != strconv.Itoa(len(content)) {
		t.Errorf("Content-Length = %q, want plaintext %d", got, len(content))
	}
	if want := `"sha256:` + sha256hex(content) + `"`; res.header.Get("ETag") != want {
		t.Errorf("ETag = %q, want plaintext %q", res.header.Get("ETag"), want)
	}
	if string(res.body) != content {
		t.Errorf("body = %q, want plaintext %q", res.body, content)
	}
}

// TestAtRestRangeCrossesChunks requests ranges that straddle chunk boundaries:
// the resolved range, Content-Range, and bytes are all in plaintext
// coordinates.
func TestAtRestRangeCrossesChunks(t *testing.T) {
	const content = "0123456789abcdefghijklmnopqrstuv" // 32 bytes, chunks of 8
	f := newAtRestFixture(t, 8, map[string]string{"a.bin": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	res := f.get(t, id, tok, map[string]string{"Range": "bytes=5-19"})
	if res.status != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", res.status)
	}
	if got, want := res.header.Get("Content-Range"), "bytes 5-19/32"; got != want {
		t.Errorf("Content-Range = %q, want %q", got, want)
	}
	if string(res.body) != content[5:20] {
		t.Errorf("body = %q, want %q", res.body, content[5:20])
	}

	res = f.get(t, id, tok, map[string]string{"Range": "bytes=-6"})
	if res.status != http.StatusPartialContent {
		t.Fatalf("suffix status = %d, want 206", res.status)
	}
	if string(res.body) != content[len(content)-6:] {
		t.Errorf("suffix body = %q, want %q", res.body, content[len(content)-6:])
	}
}

// TestAtRestZeroByteObject delivers an empty encrypted object: the envelope on
// disk is not empty, but the client sees a zero-byte plaintext.
func TestAtRestZeroByteObject(t *testing.T) {
	f := newAtRestFixture(t, 8, map[string]string{"empty.bin": ""})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	if stored := f.records[id].StoredSize; stored == 0 {
		t.Fatal("envelope stored size = 0, want the non-empty envelope")
	}
	res := f.get(t, id, tok, nil)
	if res.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.status)
	}
	if got := res.header.Get("Content-Length"); got != "0" {
		t.Errorf("Content-Length = %q, want 0", got)
	}
	if len(res.body) != 0 {
		t.Errorf("body = %q, want empty", res.body)
	}
}

// TestAtRestCorruptedHeaderFailsBeforeStreaming corrupts the envelope header on
// disk after indexing: the provider rejects it before any status is written, so
// delivery answers a clean 500 with no body.
func TestAtRestCorruptedHeaderFailsBeforeStreaming(t *testing.T) {
	const content = "payload to corrupt"
	f := newAtRestFixture(t, 8, map[string]string{"a.bin": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	corruptStored(t, f.records[id].Location, 0) // break the magic

	res := f.get(t, id, tok, nil)
	if res.status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", res.status)
	}
}

// TestAtRestCorruptedChunkLeaksNoPlaintext corrupts a ciphertext byte, which
// authentication cannot catch until the chunk is opened mid-stream — after the
// 200 header is already sent. The guarantee that survives is the one that
// matters: the client never receives the plaintext, only a truncated body, so
// no unauthenticated bytes are delivered (delivery.go streams from an
// authenticating reader).
func TestAtRestCorruptedChunkLeaksNoPlaintext(t *testing.T) {
	const content = "payload the client must never see corrupted"
	f := newAtRestFixture(t, 8, map[string]string{"a.bin": content})
	id := f.ids[0]
	tok := f.accessToken(t, id)

	// A byte in the first chunk's ciphertext, past the 16-byte envelope header.
	const envelopeHeaderLen = 16
	corruptStored(t, f.records[id].Location, envelopeHeaderLen+2)

	// The read may end in an unexpected EOF: the handler sent a Content-Length
	// for the plaintext, then the chunk failed to open and the stream was cut.
	// Either way the client must not end up holding the plaintext.
	req, err := http.NewRequest(http.MethodGet, f.dataURL(id), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) == content {
		t.Fatal("delivery returned the plaintext of a tampered object")
	}
}

// corruptStored flips one byte at pos in the file at loc.
func corruptStored(t *testing.T, loc string, pos int) {
	t.Helper()
	b, err := os.ReadFile(loc)
	if err != nil {
		t.Fatal(err)
	}
	b[pos] ^= 0xff
	if err := os.WriteFile(loc, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
