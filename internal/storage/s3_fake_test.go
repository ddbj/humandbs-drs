package storage

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// fakeObject is one stored object in the in-memory S3.
type fakeObject struct {
	data     []byte
	metadata map[string]string
	modTime  time.Time
}

// fakeS3 stands in for the S3 client at the s3API boundary. It is faithful to
// the parts the backend depends on: ranged and whole-object GETs, metadata
// heads, and paginated prefix lists. Tests drive the backend against it rather
// than mocking the backend's own logic. It is not safe for concurrent use,
// which the backend never needs.
type fakeS3 struct {
	objects  map[string]fakeObject
	pageSize int // max keys per ListObjectsV2 page; 0 lists everything at once
	now      time.Time
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: map[string]fakeObject{}, now: time.Unix(1_700_000_000, 0).UTC()}
}

// putRaw stores an object directly, bypassing the backend, so a test can plant a
// foreign object (no DRS metadata) or a specific payload.
func (f *fakeS3) putRaw(key string, data []byte, metadata map[string]string) {
	f.objects[key] = fakeObject{data: data, metadata: metadata, modTime: f.now}
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	obj, ok := f.objects[aws.ToString(in.Key)]
	if !ok {
		return nil, &types.NoSuchKey{}
	}
	if in.Range == nil {
		return &s3.GetObjectOutput{
			Body:          io.NopCloser(strings.NewReader(string(obj.data))),
			ContentLength: aws.Int64(int64(len(obj.data))),
		}, nil
	}

	start, err := parseRangeStart(aws.ToString(in.Range))
	if err != nil {
		return nil, err
	}
	size := int64(len(obj.data))
	if start >= size {
		return nil, &smithy.GenericAPIError{Code: "InvalidRange", Message: "the requested range is not satisfiable"}
	}
	chunk := obj.data[start:]

	return &s3.GetObjectOutput{
		Body:          io.NopCloser(strings.NewReader(string(chunk))),
		ContentLength: aws.Int64(int64(len(chunk))),
		ContentRange:  aws.String(fmt.Sprintf("bytes %d-%d/%d", start, size-1, size)),
	}, nil
}

func (f *fakeS3) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	obj, ok := f.objects[aws.ToString(in.Key)]
	if !ok {
		return nil, &types.NotFound{}
	}

	return &s3.HeadObjectOutput{
		ContentLength: aws.Int64(int64(len(obj.data))),
		LastModified:  aws.Time(obj.modTime),
		Metadata:      cloneMeta(obj.metadata),
	}, nil
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	data, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	f.putRaw(aws.ToString(in.Key), data, cloneMeta(in.Metadata))

	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	prefix := aws.ToString(in.Prefix)
	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	start := 0
	if in.ContinuationToken != nil {
		start = sort.SearchStrings(keys, aws.ToString(in.ContinuationToken))
	}
	end := len(keys)
	truncated := false
	if f.pageSize > 0 && end-start > f.pageSize {
		end = start + f.pageSize
		truncated = true
	}

	contents := make([]types.Object, 0, end-start)
	for _, k := range keys[start:end] {
		obj := f.objects[k]
		contents = append(contents, types.Object{
			Key:          aws.String(k),
			Size:         aws.Int64(int64(len(obj.data))),
			LastModified: aws.Time(obj.modTime),
		})
	}
	out := &s3.ListObjectsV2Output{Contents: contents, IsTruncated: aws.Bool(truncated)}
	if truncated {
		out.NextContinuationToken = aws.String(keys[end])
	}

	return out, nil
}

// parseRangeStart reads the start offset of a "bytes=N-" open-ended range, the
// only form the backend issues.
func parseRangeStart(header string) (int64, error) {
	spec := strings.TrimSuffix(strings.TrimPrefix(header, "bytes="), "-")
	n, err := strconv.ParseInt(spec, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("fakeS3: unexpected range header %q", header)
	}

	return n, nil
}

func cloneMeta(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}

	return c
}
