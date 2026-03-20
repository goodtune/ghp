package gitcache

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage"
)

// ManagedRepository represents a cached bare repository mirror. It wraps a
// go-git repository and provides thread-safe fetch, object existence checks,
// and ref comparison against upstream.
type ManagedRepository struct {
	owner       string
	name        string
	upstreamURL *url.URL
	store       storage.Storer
	repo        *git.Repository

	mu         sync.Mutex // serialises fetchUpstream
	lastUpdate time.Time
}

// openManagedRepository opens or initialises a cached bare repository backed
// by the given Storer. If the storer is empty (no HEAD reference), it
// initialises a bare repository and adds the upstream remote.
func openManagedRepository(owner, name string, upstream *url.URL, store storage.Storer) (*ManagedRepository, error) {
	m := &ManagedRepository{
		owner:       owner,
		name:        name,
		upstreamURL: upstream,
		store:       store,
	}

	// Try to open an existing repository.
	repo, err := git.Open(store, nil)
	if err != nil {
		// Initialise a new bare repository.
		repo, err = git.Init(store, nil)
		if err != nil {
			return nil, fmt.Errorf("init bare repo for %s/%s: %w", owner, name, err)
		}
		// Add the upstream remote with mirror-fetch refspec.
		_, err = repo.CreateRemote(&config.RemoteConfig{
			Name: "origin",
			URLs: []string{upstream.String()},
			Fetch: []config.RefSpec{
				config.RefSpec("+refs/*:refs/*"),
			},
		})
		if err != nil {
			return nil, fmt.Errorf("create remote for %s/%s: %w", owner, name, err)
		}
	}
	m.repo = repo
	return m, nil
}

// LastUpdateTime returns the time of the most recent successful upstream fetch.
func (m *ManagedRepository) LastUpdateTime() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastUpdate
}

// HasAllWants checks whether all requested objects and refs exist in the
// local cache. Returns true only if every want is satisfied locally.
func (m *ManagedRepository) HasAllWants(hashes []plumbing.Hash, refs []string) (bool, error) {
	storer := m.repo.Storer

	for _, h := range hashes {
		if err := storer.HasEncodedObject(h); err != nil {
			if err == plumbing.ErrObjectNotFound {
				return false, nil
			}
			return false, fmt.Errorf("check object %s: %w", h, err)
		}
	}

	for _, refName := range refs {
		_, err := storer.Reference(plumbing.ReferenceName(refName))
		if err == plumbing.ErrReferenceNotFound {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("check ref %s: %w", refName, err)
		}
	}

	return true, nil
}

// HasAnyUpdate compares upstream refs (from an ls-refs response) against
// the local cache. Returns true if any ref is new or has a different hash.
func (m *ManagedRepository) HasAnyUpdate(upstreamRefs map[string]plumbing.Hash) (bool, error) {
	storer := m.repo.Storer
	for refName, hash := range upstreamRefs {
		ref, err := storer.Reference(plumbing.ReferenceName(refName))
		if err == plumbing.ErrReferenceNotFound {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("check ref %s: %w", refName, err)
		}
		if ref.Hash() != hash {
			return true, nil
		}
	}
	return false, nil
}

// FetchUpstream fetches all refs from the upstream remote into the local
// cache. Only one fetch runs at a time per repository; concurrent calls
// block until the in-progress fetch completes.
//
// The token parameter is the GitHub credential to use for authentication.
// For async cache warming this should be a GitHub App installation token.
func (m *ManagedRepository) FetchUpstream(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	start := time.Now()
	slog.Info("fetching upstream", "repo", m.owner+"/"+m.name)

	err := m.repo.FetchContext(ctx, &git.FetchOptions{
		RemoteName: "origin",
		Force:      true,
		Auth: &http.BasicAuth{
			Username: "x-access-token",
			Password: token,
		},
		Tags: git.AllTags,
	})
	if err == git.NoErrAlreadyUpToDate {
		err = nil
	}
	if err != nil {
		slog.Error("fetch upstream failed", "repo", m.owner+"/"+m.name, "err", err, "duration", time.Since(start))
		return fmt.Errorf("fetch %s/%s: %w", m.owner, m.name, err)
	}

	m.lastUpdate = start
	slog.Info("fetch upstream complete", "repo", m.owner+"/"+m.name, "duration", time.Since(start))
	return nil
}

// Storer returns the underlying go-git Storer for direct object access
// (used by pack generation).
func (m *ManagedRepository) Storer() storage.Storer {
	return m.store
}
