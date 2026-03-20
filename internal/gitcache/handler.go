package gitcache

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
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
			// Extract the auth token from the request for use as a fallback
			// when no service token function is configured.
			authToken := extractGitHubToken(r.Header.Get("Authorization"))
			result, err := h.handleFetch(r.Context(), managed, cmd, w, authToken)
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

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
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
					warmCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
					defer cancel()
					svcToken, tokenErr := h.serviceTokenFn(warmCtx)
					if tokenErr != nil {
						slog.Error("get service token for cache warming", "repo", repo.owner+"/"+repo.name, "err", tokenErr)
						metrics.CacheWarmTotal.WithLabelValues("error").Inc()
						return
					}
					if fetchErr := repo.FetchUpstream(warmCtx, svcToken); fetchErr != nil {
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
func (h *Handler) handleFetch(ctx context.Context, repo *ManagedRepository, cmd Command, w io.Writer, authToken string) (CacheResult, error) {
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
		if err := h.fetchAndWait(ctx, repo, wantHashes, wantRefs, authToken); err != nil {
			WriteError(w, "ERR upstream fetch failed")
			return CacheError, err
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
// objects are available, or the context is cancelled. When serviceTokenFn
// is nil, authToken (the per-request credential) is used as a fallback.
func (h *Handler) fetchAndWait(ctx context.Context, repo *ManagedRepository, wantHashes []plumbing.Hash, wantRefs []string, authToken string) error {
	var svcToken string
	if h.serviceTokenFn != nil {
		var err error
		svcToken, err = h.serviceTokenFn(ctx)
		if err != nil {
			return fmt.Errorf("get service token: %w", err)
		}
	} else if authToken != "" {
		svcToken = authToken
	} else {
		return fmt.Errorf("cache miss handling unavailable: no token available")
	}

	// Fetch synchronously — no concurrent storer access to avoid data races
	// with go-git storers that are not safe for concurrent reads/writes.
	if err := repo.FetchUpstream(ctx, svcToken); err != nil {
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
}

// extractGitHubToken extracts the raw GitHub token from an Authorization
// header, handling the schemes git clients use:
//   - "Bearer <token>" / "token <token>" → token
//   - "Basic <base64(x-access-token:token)>" → token (password portion)
//   - raw value → returned as-is
func extractGitHubToken(authHeader string) string {
	authHeader = strings.TrimSpace(authHeader)
	if authHeader == "" {
		return ""
	}
	lower := strings.ToLower(authHeader)
	// Bearer and token schemes: value after the scheme is the token.
	for _, prefix := range []string{"bearer ", "token "} {
		if strings.HasPrefix(lower, prefix) {
			return strings.TrimSpace(authHeader[len(prefix):])
		}
	}
	// Basic auth: base64-decode and take the password portion.
	if strings.HasPrefix(lower, "basic ") {
		encoded := strings.TrimSpace(authHeader[len("basic "):])
		decoded, err := base64Decode(encoded)
		if err == nil {
			if _, pass, ok := strings.Cut(decoded, ":"); ok {
				return pass
			}
		}
	}
	return authHeader
}

func base64Decode(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
