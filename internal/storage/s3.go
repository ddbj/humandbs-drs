package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/google/uuid"
)

// Object metadata keys the s3 backend burns into every DRS-minted object. The
// id makes the canonical DRS id recoverable after the index is nuked, and the
// dataset url carries the object's dataset membership, so a HeadObject alone
// rebuilds an index row (architecture.md § "object ID scheme", § "index").
const (
	metaKeyID         = "drs-id"
	metaKeyDatasetURL = "drs-dataset-url"
)

// s3API is the slice of the S3 client the backend uses. The real
// *s3.Client satisfies it, and tests substitute an in-memory fake at this
// boundary rather than mocking the backend's own logic.
type s3API interface {
	GetObject(ctx context.Context, in *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(ctx context.Context, in *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	PutObject(ctx context.Context, in *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	ListObjectsV2(ctx context.Context, in *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

// S3Config configures an S3 backend against a SeaweedFS (or S3-compatible)
// endpoint. SeaweedFS serves path-style URLs, so ForcePathStyle is normally
// true. KeyPrefix scopes the bucket to the objects this backend owns, so a
// shared bucket stays safe.
type S3Config struct {
	Endpoint       string
	Region         string
	Bucket         string
	KeyPrefix      string
	AccessKey      string
	SecretKey      string
	ForcePathStyle bool
}

// S3Backend DRS-ifies an S3 bucket: it mints a UUID for each uploaded object
// and burns it into object metadata, so scanning the bucket restores the same
// DRS ids without any stored state, and it streams object bytes with range
// reads for delivery (architecture.md § "storage backend と暗号化", § "index").
type S3Backend struct {
	api       s3API
	bucket    string
	keyPrefix string
}

// NewS3Backend builds a backend over the configured bucket, wiring an S3 client
// with static credentials at the given endpoint. It does no network IO; the
// first request happens on Scan or Open.
func NewS3Backend(cfg S3Config) (*S3Backend, error) {
	if cfg.Endpoint == "" || cfg.Bucket == "" {
		return nil, fmt.Errorf("%w: s3 backend needs an endpoint and bucket", ErrInvalidManifest)
	}
	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(cfg.Endpoint),
		Region:       cfg.Region,
		Credentials:  credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		UsePathStyle: cfg.ForcePathStyle,
	})

	return newS3Backend(client, cfg.Bucket, cfg.KeyPrefix), nil
}

// newS3Backend wraps an s3API. It is the seam tests inject a fake through.
func newS3Backend(api s3API, bucket, keyPrefix string) *S3Backend {
	return &S3Backend{api: api, bucket: bucket, keyPrefix: keyPrefix}
}

// Scan lists the bucket under the configured prefix and heads each object to
// read its DRS id, dataset, size, and modification time. ListObjectsV2 does not
// return user metadata, so the head is where the id and dataset come from. An
// object missing either key is not DRS-minted (a foreign object sharing the
// bucket) and is skipped, mirroring how the filesystem backend skips non-payload
// files.
func (b *S3Backend) Scan(ctx context.Context, visit func(Entry) error) error {
	var token *string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		out, err := b.api.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(b.bucket),
			Prefix:            prefixPtr(b.keyPrefix),
			ContinuationToken: token,
		})
		if err != nil {
			return fmt.Errorf("storage: list s3 bucket %q: %w", b.bucket, err)
		}
		for _, obj := range out.Contents {
			if err := ctx.Err(); err != nil {
				return err
			}
			entry, ok, err := b.headEntry(ctx, aws.ToString(obj.Key))
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			if err := visit(entry); err != nil {
				return err
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			return nil
		}
		token = out.NextContinuationToken
	}
}

// headEntry heads key and builds its Entry from the object metadata. ok is
// false when the object lacks the DRS metadata, so it is not one this backend
// minted.
func (b *S3Backend) headEntry(ctx context.Context, key string) (Entry, bool, error) {
	out, err := b.api.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(b.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return Entry{}, false, fmt.Errorf("storage: head s3 object %q: %w", key, err)
	}
	id, hasID := metaGet(out.Metadata, metaKeyID)
	datasetURL, hasURL := metaGet(out.Metadata, metaKeyDatasetURL)
	if !hasID || !hasURL {
		return Entry{}, false, nil
	}

	return Entry{
		ID:         id,
		DatasetURL: datasetURL,
		Location:   key,
		Size:       aws.ToInt64(out.ContentLength),
		ModTime:    aws.ToTime(out.LastModified),
	}, true, nil
}

// Open returns a lazy, seekable reader over the object at loc (an S3 key). loc
// must lie under the configured prefix, so a stale or tampered index cannot
// reach objects outside this backend's scope (ErrLocationOutsideRoot). No bytes
// are fetched until the first Read, so a HEAD delivery request opens nothing.
func (b *S3Backend) Open(ctx context.Context, loc string) (io.ReadSeekCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if loc == "" || !strings.HasPrefix(loc, b.keyPrefix) {
		return nil, fmt.Errorf("%w: %q", ErrLocationOutsideRoot, loc)
	}

	return &s3Reader{ctx: ctx, api: b.api, bucket: b.bucket, key: loc, size: -1}, nil
}

// Put stores body as a new object under a minted UUID, burning the id and
// datasetURL into object metadata so a later Scan recovers the same Entry. It
// returns the object's Entry with its stat filled from a head, matching what
// Scan would produce. datasetURL must be printable ASCII, the constraint S3
// user-metadata header values carry.
func (b *S3Backend) Put(ctx context.Context, datasetURL string, body io.Reader) (Entry, error) {
	return b.PutWithID(ctx, uuid.NewString(), datasetURL, body)
}

// PutWithID stores body under the caller-supplied DRS id instead of minting
// one, so an object can be restored or pre-assigned with a known id. The id
// must be a canonical lowercase UUID string: ingested objects follow the same
// s3 object ID scheme as minted ones (architecture.md § "object ID scheme"),
// and rejecting non-canonical spellings keeps one UUID from appearing under
// two ids. Everything else matches Put.
func (b *S3Backend) PutWithID(ctx context.Context, id, datasetURL string, body io.Reader) (Entry, error) {
	if parsed, err := uuid.Parse(id); err != nil || parsed.String() != id {
		return Entry{}, fmt.Errorf("%w: %q is not a canonical UUID", ErrInvalidID, id)
	}
	if err := validateDatasetMeta(datasetURL); err != nil {
		return Entry{}, err
	}
	key := b.keyPrefix + id
	if _, err := b.api.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(b.bucket),
		Key:    aws.String(key),
		Body:   body,
		Metadata: map[string]string{
			metaKeyID:         id,
			metaKeyDatasetURL: datasetURL,
		},
	}); err != nil {
		return Entry{}, fmt.Errorf("storage: put s3 object %q: %w", key, err)
	}

	entry, ok, err := b.headEntry(ctx, key)
	if err != nil {
		return Entry{}, err
	}
	if !ok {
		return Entry{}, fmt.Errorf("storage: put s3 object %q: stored object is missing its DRS metadata", key)
	}

	return entry, nil
}

// validateDatasetMeta rejects a dataset url that S3 cannot carry verbatim as a
// user-metadata header value: empty, or holding a byte outside printable ASCII
// (which also excludes the NUL that keeps ObjectID injective).
func validateDatasetMeta(datasetURL string) error {
	if datasetURL == "" {
		return fmt.Errorf("%w: dataset_resource_url is empty", ErrInvalidManifest)
	}
	for _, r := range datasetURL {
		if r < 0x20 || r > 0x7e {
			return fmt.Errorf("%w: dataset_resource_url must be printable ASCII for s3 metadata", ErrInvalidManifest)
		}
	}

	return nil
}

// metaGet reads key from S3 object metadata case-insensitively, since the
// header names metadata rides on are case-insensitive.
func metaGet(m map[string]string, key string) (string, bool) {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}

	return "", false
}

// prefixPtr turns a possibly-empty prefix into the pointer ListObjectsV2 wants:
// nil for the whole bucket, a pointer otherwise.
func prefixPtr(p string) *string {
	if p == "" {
		return nil
	}

	return aws.String(p)
}

// s3Reader is a lazy, seekable reader over one S3 object. It holds a logical
// position and, on the next Read, issues a ranged GET from it; a Seek only
// repositions and drops the open body so the following Read re-fetches. This
// satisfies io.ReadSeekCloser without buffering the whole object and matches how
// delivery and the encryption providers read: none seeks once and copies a
// range, at-rest seeks to each chunk and reads it (storage.ReadRange, atrest.go).
type s3Reader struct {
	ctx    context.Context
	api    s3API
	bucket string
	key    string
	pos    int64
	size   int64 // object size in bytes, or -1 until learned from a GET or head
	body   io.ReadCloser
}

// Read fetches from the current position, opening a ranged GET when no stream is
// live. A bytes=pos- GET streams to the object end, so the stream's EOF is the
// object's end; a range that starts at or past the end reads nothing.
func (r *s3Reader) Read(p []byte) (int, error) {
	if r.size >= 0 && r.pos >= r.size {
		return 0, io.EOF
	}
	if r.body == nil {
		if err := r.openAt(r.pos); err != nil {
			if isRangeNotSatisfiable(err) {
				if r.size < 0 {
					r.size = r.pos
				}

				return 0, io.EOF
			}

			return 0, err
		}
	}

	n, err := r.body.Read(p)
	start := r.pos
	r.pos += int64(n)
	if errors.Is(err, io.EOF) {
		_ = r.body.Close()
		r.body = nil
		if r.size < 0 {
			r.size = r.pos
		}

		return n, io.EOF
	}
	if err != nil {
		return n, fmt.Errorf("storage: read s3 object %q at %d: %w", r.key, start, err)
	}

	return n, nil
}

// Seek repositions in object coordinates and invalidates any open stream so the
// next Read re-fetches from the new position. Seeking from the end learns the
// size with a head when it is not yet known.
func (r *s3Reader) Seek(offset int64, whence int) (int64, error) {
	var base int64
	switch whence {
	case io.SeekStart:
		base = 0
	case io.SeekCurrent:
		base = r.pos
	case io.SeekEnd:
		if r.size < 0 {
			if err := r.fetchSize(); err != nil {
				return 0, err
			}
		}
		base = r.size
	default:
		return 0, fmt.Errorf("storage: seek s3 object %q: invalid whence %d", r.key, whence)
	}
	pos := base + offset
	if pos < 0 {
		return 0, fmt.Errorf("storage: seek s3 object %q: negative position %d", r.key, pos)
	}
	if r.body != nil {
		_ = r.body.Close()
		r.body = nil
	}
	r.pos = pos

	return pos, nil
}

// Close releases the open stream, if any.
func (r *s3Reader) Close() error {
	if r.body == nil {
		return nil
	}
	err := r.body.Close()
	r.body = nil

	return err
}

// openAt issues the GET that backs the next Read: the whole object at position
// zero (so an empty object reads cleanly), a bytes=pos- range otherwise. It
// learns the object size from the response so later reads can stop at the end.
func (r *s3Reader) openAt(pos int64) error {
	in := &s3.GetObjectInput{Bucket: aws.String(r.bucket), Key: aws.String(r.key)}
	if pos > 0 {
		in.Range = aws.String("bytes=" + strconv.FormatInt(pos, 10) + "-")
	}
	out, err := r.api.GetObject(r.ctx, in)
	if err != nil {
		return fmt.Errorf("storage: get s3 object %q at %d: %w", r.key, pos, err)
	}
	if total, ok := totalSize(out, pos); ok {
		r.size = total
	}
	r.body = out.Body

	return nil
}

// fetchSize heads the object to learn its size for an end-relative seek.
func (r *s3Reader) fetchSize() error {
	out, err := r.api.HeadObject(r.ctx, &s3.HeadObjectInput{
		Bucket: aws.String(r.bucket),
		Key:    aws.String(r.key),
	})
	if err != nil {
		return fmt.Errorf("storage: head s3 object %q: %w", r.key, err)
	}
	r.size = aws.ToInt64(out.ContentLength)

	return nil
}

// totalSize derives the object's total size from a GET response: the value after
// the slash of a Content-Range, or the content length added to the start offset
// of a whole-object read.
func totalSize(out *s3.GetObjectOutput, pos int64) (int64, bool) {
	if out.ContentRange != nil {
		if idx := strings.LastIndex(*out.ContentRange, "/"); idx >= 0 {
			if total, err := strconv.ParseInt((*out.ContentRange)[idx+1:], 10, 64); err == nil {
				return total, true
			}
		}
	}
	if out.ContentLength != nil {
		return pos + *out.ContentLength, true
	}

	return 0, false
}

// isRangeNotSatisfiable reports whether err is S3's response to a range that
// starts at or past the object end, which the reader treats as EOF.
func isRangeNotSatisfiable(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "InvalidRange"
	}

	return false
}
