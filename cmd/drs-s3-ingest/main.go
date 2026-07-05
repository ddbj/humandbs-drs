// Command drs-s3-ingest stores a local file as a DRS object in an s3 backend
// bucket: it creates the bucket when missing, burns the DRS id and dataset
// resource URL into object metadata, and verifies the stored metadata by
// reading it back, so a later index rebuild recovers the object
// (architecture.md § "object ID scheme", § "index"). The assigned id is
// printed to stdout.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"

	"github.com/ddbj/humandbs-drs/internal/buildinfo"
	"github.com/ddbj/humandbs-drs/internal/storage"
)

const toolName = "drs-s3-ingest"

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, toolName+":", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(stdout)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stdout, "usage: "+toolName+" -endpoint <url> -bucket <name> -dataset <resource url> [-id <uuid>] <file>")
		fs.PrintDefaults()
	}
	showVersion := fs.Bool("version", false, "print version and exit")
	endpoint := fs.String("endpoint", "", "s3 endpoint URL (required)")
	bucket := fs.String("bucket", "", "bucket name, created when missing (required)")
	region := fs.String("region", "us-east-1", "s3 signing region")
	accessKey := fs.String("access-key", "", "s3 access key (required)")
	secretKey := fs.String("secret-key", "", "s3 secret key (required)")
	keyPrefix := fs.String("key-prefix", "", "key prefix scoping the backend's objects")
	dataset := fs.String("dataset", "", "dataset resource URL the object belongs to (required)")
	id := fs.String("id", "", "DRS id to assign, a canonical lowercase UUID (default: mint one)")
	forcePathStyle := fs.Bool("force-path-style", true, "use path-style addressing (SeaweedFS serves path-style URLs)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return err
	}

	if *showVersion {
		_, err := fmt.Fprintln(stdout, toolName+" "+buildinfo.String())

		return err
	}

	if *endpoint == "" || *bucket == "" || *dataset == "" || *accessKey == "" || *secretKey == "" {
		return errors.New("endpoint, bucket, dataset, access-key, and secret-key are required")
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("expected one <file> argument, got %d", fs.NArg())
	}
	objectID := *id
	if objectID == "" {
		objectID = uuid.NewString()
	} else if parsed, err := uuid.Parse(objectID); err != nil || parsed.String() != objectID {
		// The backend enforces the same rule (storage.ErrInvalidID); checking
		// here as well fails before a bad id creates the bucket.
		return fmt.Errorf("id %q is not a canonical lowercase UUID", objectID)
	}

	cfg := storage.S3Config{
		Endpoint:       *endpoint,
		Region:         *region,
		Bucket:         *bucket,
		KeyPrefix:      *keyPrefix,
		AccessKey:      *accessKey,
		SecretKey:      *secretKey,
		ForcePathStyle: *forcePathStyle,
	}
	if err := ensureBucket(ctx, cfg); err != nil {
		return err
	}
	backend, err := storage.NewS3Backend(cfg)
	if err != nil {
		return err
	}

	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	entry, err := backend.PutWithID(ctx, objectID, *dataset, f)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, entry.ID)

	return err
}

// ensureBucket creates the bucket, treating an already-existing one as
// success so repeated ingests into one bucket are idempotent.
func ensureBucket(ctx context.Context, cfg storage.S3Config) error {
	client := s3.New(s3.Options{
		BaseEndpoint: aws.String(cfg.Endpoint),
		Region:       cfg.Region,
		Credentials:  credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		UsePathStyle: cfg.ForcePathStyle,
	})
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(cfg.Bucket)})
	var owned *types.BucketAlreadyOwnedByYou
	var exists *types.BucketAlreadyExists
	if errors.As(err, &owned) || errors.As(err, &exists) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create bucket %q: %w", cfg.Bucket, err)
	}

	return nil
}
