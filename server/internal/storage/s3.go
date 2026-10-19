package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// BlobConfig configures the S3-compatible blob store (SeaweedFS S3 gateway
// in development, any S3-compatible store in production).
type BlobConfig struct {
	Endpoint  string // e.g. http://localhost:8333
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	// PathStyle forces path-style addressing (required by SeaweedFS).
	PathStyle bool
}

// BlobStore is a minimal S3 object store wrapper.
type BlobStore struct {
	client *s3.Client
	bucket string
}

// NewBlobStore connects to an S3-compatible endpoint. Connectivity is
// validated lazily; a missing bucket surfaces on first use.
func NewBlobStore(_ context.Context, cfg BlobConfig) (*BlobStore, error) {
	creds := credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")
	awsCfg := aws.Config{
		Region:       cfg.Region,
		Credentials:  creds,
		BaseEndpoint: aws.String(cfg.Endpoint),
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = cfg.PathStyle
	})
	return &BlobStore{client: client, bucket: cfg.Bucket}, nil
}

// EnsureBucket creates the configured bucket when it does not exist.
//
// A fresh SeaweedFS or MinIO has no buckets, and Put fails with NoSuchBucket
// until one is created. Doing this at boot is what makes "set S3_ENDPOINT and
// start" a complete instruction instead of one that requires an operator to
// remember an out-of-band `mc mb`. A bucket that already exists is not an error
// (that is the steady state), and an endpoint that does not implement
// CreateBucket is only logged by the caller: the store stays usable against a
// pre-provisioned bucket.
func (b *BlobStore) EnsureBucket(ctx context.Context) error {
	if b == nil || b.bucket == "" {
		return nil
	}
	_, err := b.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(b.bucket)})
	if err == nil {
		return nil
	}
	if _, cerr := b.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(b.bucket)}); cerr != nil {
		return fmt.Errorf("ensure bucket %q: %w (head: %v)", b.bucket, cerr, err)
	}
	return nil
}

// Put uploads data under key (deduplicated by content hash upstream).
func (b *BlobStore) Put(ctx context.Context, key string, data []byte) error {
	_, err := b.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(b.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("s3 put %s: %w", key, err)
	}
	return nil
}

// Get downloads the object at key.
func (b *BlobStore) Get(ctx context.Context, key string) ([]byte, error) {
	out, err := b.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("s3 get %s: %w", key, err)
	}
	defer out.Body.Close()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("s3 read %s: %w", key, err)
	}
	return data, nil
}
