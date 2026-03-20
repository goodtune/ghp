package gitcache

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/google/gitprotocolio"

	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/proxy"
)

// CacheResult describes the outcome of a cache operation for logging and
// metrics.
type CacheResult string

const (
	CacheHit      CacheResult = "hit"
	CacheMiss     CacheResult = "miss"
	CacheRejected CacheResult = "rejected"
	CacheError    CacheResult = "error"
)

// ServiceTokenFunc returns a GitHub App installation token for async
// cache warming. Unlike per-request tokens, this is not tied to a specific
// user's credential. May be nil if async warming is not configured.
type ServiceTokenFunc func(ctx context.Context) (string, error)

// Handler implements the Git protocol v2 caching proxy as an http.Handler.
// It is intended to be mounted for requests to cache-enabled repositories
// after token resolution and scope enforcement have already occurred.
// The upstream GitHub token is extracted from the request's Authorization
// header, which is set by the scoped passthrough handler.
type Handler struct {
	registry        *Registry
	serviceTokenFn  ServiceTokenFunc
	upstreamBaseURL string // e.g. "https://github.com"
	checkFrequency  time.Duration
}

// NewHandler creates a cache handler.
//
//   - registry: manages local bare repo mirrors
//   - serviceTokenFn: returns a service-level token for async cache warming
//     (may be nil to disable async warming)
//   - upstreamBaseURL: the upstream Git server (e.g. "https://github.com")
func NewHandler(registry *Registry, serviceTokenFn ServiceTokenFunc, upstreamBaseURL string) *Handler {
	return &Handler{
		registry:        registry,
		serviceTokenFn:  serviceTokenFn,
		upstreamBaseURL: upstreamBaseURL,
		checkFrequency:  1 * time.Second,
	}
}

// ServeInfoRefs handles GET /owner/repo.git/info/refs?service=git-upload-pack
// by returning synthetic protocol v2 capabilities.
func (h *Handler) ServeInfoRefs(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("service") != "git-upload-pack" {
		http.Error(w, "only git-upload-pack is supported", http.StatusBadRequest)
		return
	}
	if proto := r.Header.Get("Git-Protocol"); proto != "version=2" {
		http.Error(w, "only Git protocol v2 is supported", http.StatusBadRequest)
		return
	}
	WriteInfoRefsResponse(w)
}

// ServeUploadPack handles POST /owner/repo.git/git-upload-pack by parsing
// protocol v2 commands and serving from cache where possible.
//
// Security invariant: fetch commands are only served after a successful
// ls-refs (which verifies the user's GitHub access via upstream).
func (h *Handler) ServeUploadPack(w http.ResponseWriter, r *http.Request, owner, repo string) {
	if proto := r.Header.Get("Git-Protocol"); proto != "version=2" {
		http.Error(w, "only Git protocol v2 is supported", http.StatusBadRequest)
		return
	}

	body, err := MaybeGunzip(r)
	if err != nil {
		http.Error(w, "cannot decompress request", http.StatusBadRequest)
		return
	}
	defer body.Close()

	commands, err := ParseCommands(body)
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot parse request: %v", err), http.StatusBadRequest)
		return
	}

	managed, err := h.registry.Get(owner, repo)
	if err != nil {
		slog.Error("open cached repo", "repo", owner+"/"+repo, "err", err)
		http.Error(w, "cache error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")

	lsRefsSucceeded := false
	for _, cmd := range commands {
		switch cmd.Name {
		case "ls-refs":
			metrics.CacheLsRefsTotal.Inc()
			if err := h.handleLsRefs(r, managed, cmd, w); err != nil {
				slog.Error("ls-refs failed", "repo", owner+"/"+repo, "err", err)
				proxy.SetCacheState(r, string(CacheRejected))
				return // upstream rejected — stop, no cached data exposed
			}
			lsRefsSucceeded = true

		case "fetch":
			if !lsRefsSucceeded {
				WriteError(w, "ERR fetch requires ls-refs first for access verification")
				proxy.SetCacheState(r, string(CacheRejected))
				metrics.CacheFetchTotal.WithLabelValues(string(CacheRejected)).Inc()
				return
			}
			result, err := h.handleFetch(r.Context(), managed, cmd, w)
			proxy.SetCacheState(r, string(result))
			metrics.CacheFetchTotal.WithLabelValues(string(result)).Inc()
			if err != nil {
				slog.Error("fetch failed", "repo", owner+"/"+repo, "result", result, "err", err)
				return
			}
			slog.Info("fetch served", "repo", owner+"/"+repo, "result", result)
		}
	}
}

// handleLsRefs forwards the ls-refs command to upstream GitHub and returns
// the response to the client. This serves as the access verification gate
// and also triggers async cache warming if refs have changed.
//
// The upstream Authorization header is propagated as-is from the incoming
// request (which has already been resolved by the scoped passthrough handler),
// preserving the original auth scheme (Bearer, Basic, etc.).
func (h *Handler) handleLsRefs(r *http.Request, repo *ManagedRepository, cmd Command, w io.Writer) error {
	authHeader := r.Header.Get("Authorization")
	upstreamURL := h.upstreamBaseURL + "/" + repo.owner + "/" + repo.name + ".git/git-upload-pack"

	req, err := http.NewRequestWithContext(r.Context(), "POST", upstreamURL, EncodeCommandsToReader(cmd))
	if err != nil {
		WriteError(w, "ERR internal error")
		return fmt.Errorf("create upstream request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	req.Header.Set("Git-Protocol", "version=2")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		WriteError(w, "ERR upstream unavailable")
		return fmt.Errorf("upstream request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Forward the upstream error to the client.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		WriteError(w, fmt.Sprintf("ERR upstream: %d %s", resp.StatusCode, string(body)))
		return fmt.Errorf("upstream returned %d", resp.StatusCode)
	}

	// Parse response to check for ref changes.
	var chunks []*gitprotocolio.ProtocolV2ResponseChunk
	scanner := gitprotocolio.NewProtocolV2Response(resp.Body)
	for scanner.Scan() {
		chunks = append(chunks, copyResponseChunk(scanner.Chunk()))
	}
	if err := scanner.Err(); err != nil {
		WriteError(w, "ERR cannot parse upstream response")
		return fmt.Errorf("parse upstream response: %w", err)
	}

	// Check if any refs have changed and trigger async fetch if a service
	// token function is available.
	if h.serviceTokenFn != nil {
		refs, parseErr := ParseLsRefsResponse(chunks)
		if parseErr == nil {
			if hasUpdate, checkErr := repo.HasAnyUpdate(refs); checkErr == nil && hasUpdate {
				go func() {
					svcToken, tokenErr := h.serviceTokenFn(context.Background())
					if tokenErr != nil {
						slog.Error("get service token for cache warming", "repo", repo.owner+"/"+repo.name, "err", tokenErr)
						metrics.CacheWarmTotal.WithLabelValues("error").Inc()
						return
					}
					if fetchErr := repo.FetchUpstream(context.Background(), svcToken); fetchErr != nil {
						slog.Error("async cache warming failed", "repo", repo.owner+"/"+repo.name, "err", fetchErr)
						metrics.CacheWarmTotal.WithLabelValues("error").Inc()
					} else {
						metrics.CacheWarmTotal.WithLabelValues("success").Inc()
					}
				}()
			}
		}
	}

	// Forward the upstream response verbatim to the client.
	return WriteResponseChunks(w, chunks)
}

// handleFetch processes a fetch command, serving from local cache if all
// requested objects are available, or fetching from upstream first.
func (h *Handler) handleFetch(ctx context.Context, repo *ManagedRepository, cmd Command, w io.Writer) (CacheResult, error) {
	wantHashes, wantRefs, err := ParseFetchWants(cmd)
	if err != nil {
		WriteError(w, "ERR malformed fetch request")
		return CacheError, err
	}
	haves := ParseFetchHaves(cmd)

	// Check if all wants are satisfied locally.
	hasAll, err := repo.HasAllWants(wantHashes, wantRefs)
	if err != nil {
		WriteError(w, "ERR cache lookup error")
		return CacheError, err
	}

	if !hasAll {
		// Cache miss — need to fetch from upstream first.
		if err := h.fetchAndWait(ctx, repo, wantHashes, wantRefs); err != nil {
			WriteError(w, "ERR upstream fetch failed")
			return CacheMiss, err
		}
	}

	result := CacheHit
	if !hasAll {
		result = CacheMiss
	}

	// Resolve want-refs to hashes.
	s := repo.Storer()
	objStorer, ok := s.(storer.EncodedObjectStorer)
	if !ok {
		WriteError(w, "ERR internal cache error")
		return CacheError, fmt.Errorf("repository storer does not implement storer.EncodedObjectStorer")
	}
	refStorer, ok := s.(storer.ReferenceStorer)
	if !ok {
		WriteError(w, "ERR internal cache error")
		return CacheError, fmt.Errorf("repository storer does not implement storer.ReferenceStorer")
	}
	allWants, err := ResolveWantHashes(objStorer, refStorer, wantHashes, wantRefs)
	if err != nil {
		WriteError(w, "ERR cannot resolve refs")
		return result, err
	}

	// Generate and stream the packfile.
	if err := ServeFetchLocal(w, objStorer, allWants, haves); err != nil {
		return result, fmt.Errorf("serve pack: %w", err)
	}

	return result, nil
}

// fetchAndWait triggers an upstream fetch and polls until the requested
// objects are available, or the context is cancelled.
func (h *Handler) fetchAndWait(ctx context.Context, repo *ManagedRepository, wantHashes []plumbing.Hash, wantRefs []string) error {
	if h.serviceTokenFn == nil {
		return fmt.Errorf("cache miss handling unavailable: no service token function configured")
	}
	svcToken, err := h.serviceTokenFn(ctx)
	if err != nil {
		return fmt.Errorf("get service token: %w", err)
	}

	fetchDone := make(chan error, 1)
	go func() {
		fetchDone <- repo.FetchUpstream(ctx, svcToken)
	}()

	timer := time.NewTimer(h.checkFrequency)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-fetchDone:
			if err != nil {
				return err
			}
			// Verify objects are now available.
			hasAll, checkErr := repo.HasAllWants(wantHashes, wantRefs)
			if checkErr != nil {
				return checkErr
			}
			if !hasAll {
				return fmt.Errorf("objects still missing after fetch")
			}
			return nil
		case <-timer.C:
			// Check early — objects may appear before fetch completes.
			hasAll, err := repo.HasAllWants(wantHashes, wantRefs)
			if err != nil {
				return err
			}
			if hasAll {
				return nil
			}
			timer.Reset(h.checkFrequency)
		}
	}
}
