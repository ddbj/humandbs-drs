package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

const s3Bucket = "humandbs"

// collectScan runs Scan and returns the entries keyed by DRS id.
func collectScan(t *testing.T, b *S3Backend) map[string]Entry {
	t.Helper()
	got := map[string]Entry{}
	err := b.Scan(context.Background(), func(e Entry) error {
		if _, dup := got[e.ID]; dup {
			t.Fatalf("duplicate id %q", e.ID)
		}
		got[e.ID] = e

		return nil
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	return got
}

func TestS3BackendPutBurnsMetadataAndScanRecoversID(t *testing.T) {
	fake := newFakeS3()
	b := newS3Backend(fake, s3Bucket, "")
	ctx := context.Background()

	a, err := b.Put(ctx, urlA, strings.NewReader("aaa"))
	if err != nil {
		t.Fatalf("Put a: %v", err)
	}
	c, err := b.Put(ctx, urlB, strings.NewReader("cccc"))
	if err != nil {
		t.Fatalf("Put c: %v", err)
	}

	// The minted id and dataset are burned into object metadata, so the index
	// is recoverable from the bucket alone.
	meta := fake.objects[a.Location].metadata
	if meta[metaKeyID] != a.ID || meta[metaKeyDatasetURL] != urlA {
		t.Fatalf("object metadata = %v, want id %q and dataset %q", meta, a.ID, urlA)
	}
	if a.ID == c.ID {
		t.Fatalf("distinct objects share id %q", a.ID)
	}

	got := collectScan(t, b)
	if len(got) != 2 {
		t.Fatalf("scanned %d objects, want 2: %v", len(got), got)
	}
	for _, want := range []Entry{a, c} {
		e, ok := got[want.ID]
		if !ok {
			t.Fatalf("scan is missing id %q", want.ID)
		}
		if e.DatasetURL != want.DatasetURL || e.Location != want.Location || e.Size != want.Size {
			t.Fatalf("scanned entry %+v, want dataset/location/size of %+v", e, want)
		}
		if e.ModTime.IsZero() {
			t.Fatalf("scanned entry %q has zero ModTime", want.ID)
		}
	}

	// Nuking the index and rescanning yields the same ids, since they come from
	// metadata rather than any stored derived state.
	again := collectScan(t, b)
	for id := range got {
		if _, ok := again[id]; !ok {
			t.Fatalf("rescan lost id %q", id)
		}
	}
}

func TestS3BackendPutWithIDBurnsGivenID(t *testing.T) {
	fake := newFakeS3()
	b := newS3Backend(fake, s3Bucket, "objects/")
	ctx := context.Background()

	const id = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
	entry, err := b.PutWithID(ctx, id, urlA, strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("PutWithID: %v", err)
	}
	if entry.ID != id {
		t.Fatalf("entry id = %q, want %q", entry.ID, id)
	}
	meta := fake.objects[entry.Location].metadata
	if meta[metaKeyID] != id || meta[metaKeyDatasetURL] != urlA {
		t.Fatalf("object metadata = %v, want id %q and dataset %q", meta, id, urlA)
	}

	// Scan recovers the caller-supplied id from metadata, same as a minted one.
	got := collectScan(t, b)
	e, ok := got[id]
	if !ok {
		t.Fatalf("scan did not recover id %q: %v", id, got)
	}
	if e.DatasetURL != urlA || e.Size != int64(len("payload")) {
		t.Fatalf("scanned entry %+v, want dataset %q size %d", e, urlA, len("payload"))
	}
}

func TestS3BackendPutWithIDRejectsNonCanonicalUUID(t *testing.T) {
	fake := newFakeS3()
	b := newS3Backend(fake, s3Bucket, "")
	ctx := context.Background()

	for _, id := range []string{
		"",
		"not-a-uuid",
		"jgad000001-obj1",
		"0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", // uppercase: parses but is not canonical
		"urn:uuid:0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",       // URN form: parses but is not canonical
		"0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0 ",               // trailing space
		"0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0-extra-trailing", // overlong
	} {
		if _, err := b.PutWithID(ctx, id, urlA, strings.NewReader("x")); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("PutWithID(%q) error = %v, want ErrInvalidID", id, err)
		}
	}
	if len(fake.objects) != 0 {
		t.Fatalf("rejected put stored objects: %v", fake.objects)
	}
}

func TestS3BackendPutWithIDRejectsNonASCIIDataset(t *testing.T) {
	fake := newFakeS3()
	b := newS3Backend(fake, s3Bucket, "")

	const id = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
	_, err := b.PutWithID(context.Background(), id, "https://example.org/データ", strings.NewReader("x"))
	if !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("PutWithID error = %v, want ErrInvalidManifest", err)
	}
	if len(fake.objects) != 0 {
		t.Fatalf("rejected put stored objects: %v", fake.objects)
	}
}

func TestS3BackendUploadDownloadRoundTrip(t *testing.T) {
	fake := newFakeS3()
	b := newS3Backend(fake, s3Bucket, "objects/")
	ctx := context.Background()

	for _, content := range []string{"hello world", "", "x"} {
		entry, err := b.Put(ctx, urlA, strings.NewReader(content))
		if err != nil {
			t.Fatalf("Put %q: %v", content, err)
		}
		if !strings.HasPrefix(entry.Location, "objects/") {
			t.Fatalf("location %q is not under the key prefix", entry.Location)
		}

		rsc, err := b.Open(ctx, entry.Location)
		if err != nil {
			t.Fatalf("Open %q: %v", entry.Location, err)
		}
		got, err := io.ReadAll(rsc)
		_ = rsc.Close()
		if err != nil {
			t.Fatalf("read %q: %v", entry.Location, err)
		}
		if string(got) != content {
			t.Fatalf("downloaded %q, want %q", got, content)
		}
	}
}

func TestS3BackendOpenRangeRead(t *testing.T) {
	fake := newFakeS3()
	b := newS3Backend(fake, s3Bucket, "")
	ctx := context.Background()
	content := "the quick brown fox jumps over the lazy dog"

	entry, err := b.Put(ctx, urlA, strings.NewReader(content))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	cases := []struct {
		offset, length int64
	}{
		{0, int64(len(content))},     // whole
		{4, 5},                       // middle
		{0, 3},                       // head
		{int64(len(content)) - 3, 3}, // tail
		{10, -1},                     // to end
		{4, 100},                     // length past end, clamped
	}
	for _, c := range cases {
		rsc, err := b.Open(ctx, entry.Location)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		var buf bytes.Buffer
		n, err := ReadRange(&buf, rsc, int64(len(content)), c.offset, c.length)
		_ = rsc.Close()
		if err != nil {
			t.Fatalf("ReadRange(%d,%d): %v", c.offset, c.length, err)
		}

		want := rangeSlice(content, c.offset, c.length)
		if int(n) != len(want) || buf.String() != want {
			t.Fatalf("ReadRange(%d,%d) = %q (n=%d), want %q", c.offset, c.length, buf.String(), n, want)
		}
	}
}

// rangeSlice mirrors ReadRange's clamping for the expected value.
func rangeSlice(content string, offset, length int64) string {
	size := int64(len(content))
	if offset >= size {
		return ""
	}
	avail := size - offset
	if length < 0 || length > avail {
		length = avail
	}

	return content[offset : offset+length]
}

func TestS3BackendScanSkipsForeignObjects(t *testing.T) {
	fake := newFakeS3()
	b := newS3Backend(fake, s3Bucket, "")
	ctx := context.Background()

	if _, err := b.Put(ctx, urlA, strings.NewReader("mine")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// A foreign object without DRS metadata, and one with only a partial set.
	fake.putRaw("foreign", []byte("not mine"), map[string]string{"other": "x"})
	fake.putRaw("partial", []byte("half"), map[string]string{metaKeyID: "id-only"})

	got := collectScan(t, b)
	if len(got) != 1 {
		t.Fatalf("scanned %d objects, want 1 (foreign objects ignored): %v", len(got), got)
	}
}

func TestS3BackendScanPaginates(t *testing.T) {
	fake := newFakeS3()
	fake.pageSize = 2
	b := newS3Backend(fake, s3Bucket, "")
	ctx := context.Background()

	for range 5 {
		if _, err := b.Put(ctx, urlA, strings.NewReader("data")); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	got := collectScan(t, b)
	if len(got) != 5 {
		t.Fatalf("scanned %d objects across pages, want 5", len(got))
	}
}

func TestS3BackendScanStopsOnContextCancel(t *testing.T) {
	fake := newFakeS3()
	b := newS3Backend(fake, s3Bucket, "")
	if _, err := b.Put(context.Background(), urlA, strings.NewReader("data")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := b.Scan(ctx, func(Entry) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan error = %v, want context.Canceled", err)
	}
}

func TestS3BackendOpenRejectsOutsidePrefix(t *testing.T) {
	fake := newFakeS3()
	b := newS3Backend(fake, s3Bucket, "objects/")
	ctx := context.Background()

	for _, bad := range []string{"", "other/x", "objectsX"} {
		if _, err := b.Open(ctx, bad); !errors.Is(err, ErrLocationOutsideRoot) {
			t.Fatalf("Open(%q): error = %v, want ErrLocationOutsideRoot", bad, err)
		}
	}
}

func TestS3BackendPutRejectsNonASCIIDataset(t *testing.T) {
	fake := newFakeS3()
	b := newS3Backend(fake, s3Bucket, "")
	ctx := context.Background()

	for _, bad := range []string{"", "https://example.org/データ", "url\x00nul"} {
		if _, err := b.Put(ctx, bad, strings.NewReader("x")); !errors.Is(err, ErrInvalidManifest) {
			t.Fatalf("Put(dataset=%q): error = %v, want ErrInvalidManifest", bad, err)
		}
	}
}

func TestS3ReaderSeekEnd(t *testing.T) {
	fake := newFakeS3()
	b := newS3Backend(fake, s3Bucket, "")
	ctx := context.Background()
	content := "hello world"

	entry, err := b.Put(ctx, urlA, strings.NewReader(content))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	rsc, err := b.Open(ctx, entry.Location)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = rsc.Close() }()

	end, err := rsc.Seek(0, io.SeekEnd)
	if err != nil {
		t.Fatalf("Seek end: %v", err)
	}
	if end != int64(len(content)) {
		t.Fatalf("Seek(0, end) = %d, want %d", end, len(content))
	}
	if _, err := rsc.Seek(-5, io.SeekEnd); err != nil {
		t.Fatalf("Seek -5 from end: %v", err)
	}
	got, err := io.ReadAll(rsc)
	if err != nil {
		t.Fatalf("read tail: %v", err)
	}
	if string(got) != "world" {
		t.Fatalf("tail = %q, want %q", got, "world")
	}
}

func TestS3ReaderRangeNotSatisfiableIsEOF(t *testing.T) {
	fake := newFakeS3()
	b := newS3Backend(fake, s3Bucket, "")
	ctx := context.Background()

	entry, err := b.Put(ctx, urlA, strings.NewReader("short"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	rsc, err := b.Open(ctx, entry.Location)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = rsc.Close() }()

	// Seek past the end with the size still unknown, so the next read issues a
	// GET that S3 rejects as unsatisfiable; the reader reports EOF.
	if _, err := rsc.Seek(1000, io.SeekStart); err != nil {
		t.Fatalf("Seek: %v", err)
	}
	n, err := rsc.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read past end = (%d, %v), want (0, EOF)", n, err)
	}
}
