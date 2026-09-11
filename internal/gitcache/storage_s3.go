package gitcache

import (
	"fmt"

	"github.com/go-git/go-git/v5/storage"
)

// S3StorageFactory implements CacheStorageFactory using an S3-compatible
// object store as the backing storage for cached bare repositories.
//
// Each repository is stored under the key prefix <basePath>/<owner>/<repo>/
// within the configured bucket. The go-git Storer interface is backed by
// the filesystem storage with a local staging area, and objects are synced
// to/from S3 transparently.
//
// This backend enables horizontal scaling: multiple ghp instances can share
// the same S3 bucket and prefix, benefiting from a shared cache without
// filesystem coordination.
//
// Note: S3 does not support atomic operations, so concurrent writes to the
// same repository from different instances may result in redundant uploads.
// This is safe because git objects are content-addressed and immutable.
type S3StorageFactory struct {
	bucket   string
	region   string
	endpoint string // custom endpoint for MinIO/compatible
	basePath string // key prefix within the bucket
}

// NewS3StorageFactory creates an S3-backed storage factory.
//
// Parameters:
//   - bucket: S3 bucket name
//   - region: AWS region (e.g. "us-east-1")
//   - endpoint: custom S3-compatible endpoint (empty for AWS S3)
//   - basePath: key prefix within the bucket (e.g. "cache")
func NewS3StorageFactory(bucket, region, endpoint, basePath string) *S3StorageFactory {
	return &S3StorageFactory{
		bucket:   bucket,
		region:   region,
		endpoint: endpoint,
		basePath: basePath,
	}
}

// Open returns a go-git Storer for the given repository.
//
// TODO: Implement S3-backed Storer. This requires adding the AWS SDK
// dependency (github.com/aws/aws-sdk-go-v2). The implementation will:
//
//  1. Use a local filesystem staging area for in-progress operations
//  2. Sync objects to/from S3 on open/close
//  3. Support go-git's EncodedObjectStorer and ReferenceStorer interfaces
//
// For now, this returns an error indicating the feature is not yet available.
func (s *S3StorageFactory) Open(owner, repo string) (storage.Storer, error) {
	return nil, fmt.Errorf("S3 cache storage backend is not yet implemented; use local filesystem storage (cache.storage_path) instead")
}

// Delete removes all cached data for the given repository from S3.
//
// TODO: Implement by listing and deleting all objects under the repository's
// key prefix in the S3 bucket.
func (s *S3StorageFactory) Delete(owner, repo string) error {
	return fmt.Errorf("S3 cache storage backend is not yet implemented")
}
