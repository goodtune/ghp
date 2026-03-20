// Package gitcache implements a Git protocol v2 caching proxy for read-only
// (clone/fetch) operations. It maintains local bare repository mirrors and
// serves git objects from cache when possible, falling back to upstream
// GitHub when the cache is cold.
//
// The caching technique is inspired by Google's goblet project (Apache 2.0).
// Key invariant: ls-refs is always forwarded to upstream to verify access
// and freshness. Fetch commands are only served from cache after a
// successful ls-refs in the same request.
package gitcache

import (
	"github.com/go-git/go-git/v5/storage"
)

// CacheStorageFactory abstracts where cached git objects are stored.
// go-git's storage.Storer interface is the foundation — filesystem and S3
// backends implement this interface, making them transparent to the cache
// handler and repository management layers.
type CacheStorageFactory interface {
	// Open returns a go-git Storer for the given repository.
	// Creates the backing storage if it doesn't exist.
	Open(owner, repo string) (storage.Storer, error)

	// Delete removes all cached data for a repository.
	Delete(owner, repo string) error
}
