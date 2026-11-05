package tokens

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

type fakeTok struct {
	ID        string     `json:"id"`
	SessionID string     `json:"session_id"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	mine      bool
	hidden    bool // omitted from list responses
}

// fakeAPI mirrors the shapes of internal/server/api.go token endpoints.
type fakeAPI struct {
	mu             sync.Mutex
	toks           []*fakeTok
	next           int
	posts          []map[string]any
	deletes        map[string]int
	auth           []string
	post429        int             // number of 429s to return before succeeding
	postFail       string          // if set, return 400 with this message
	allFor403      bool            // GET ?all=true -> 403
	alreadyRevoked map[string]bool // DELETE answers 400 and marks revoked
	failDelete     map[string]bool // DELETE answers 500
	onPost         func()          // called (unlocked) before handling POST
	onDelete       func(id string) // called (unlocked) after each DELETE
}

func newFake() *fakeAPI {
	return &fakeAPI{deletes: map[string]int{}, alreadyRevoked: map[string]bool{}, failDelete: map[string]bool{}}
}

func (f *fakeAPI) find(id string) *fakeTok {
	for _, t := range f.toks {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/tokens", func(w http.ResponseWriter, r *http.Request) {
		if f.onPost != nil {
			f.onPost()
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.posts = append(f.posts, body)
		if f.post429 > 0 {
			f.post429--
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"message": "Too many requests"})
			return
		}
		if f.postFail != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": f.postFail})
			return
		}
		f.next++
		id := fmt.Sprintf("00000000-0000-0000-0000-%012d", f.next)
		sid, _ := body["session_id"].(string)
		f.toks = append(f.toks, &fakeTok{ID: id, SessionID: sid, mine: true})
		writeJSON(w, http.StatusCreated, map[string]any{
			"token": fmt.Sprintf("ghx_secret%08d", f.next), "id": id, "type": body["type"],
			"repositories": body["repositories"], "scopes": body["scopes"], "expires_at": nil, "session_id": sid,
		})
	})
	mux.HandleFunc("GET /api/tokens", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Query().Get("all") == "true" && f.allFor403 {
			writeJSON(w, http.StatusForbidden, map[string]string{"message": "Access denied"})
			return
		}
		out := make([]*fakeTok, 0)
		for _, t := range f.toks {
			if !t.hidden && (t.mine || r.URL.Query().Get("all") == "true") {
				out = append(out, t)
			}
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("GET /api/tokens/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		t := f.find(r.PathValue("id"))
		if t == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "Token not found"})
			return
		}
		writeJSON(w, http.StatusOK, t)
	})
	mux.HandleFunc("DELETE /api/tokens/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if f.onDelete != nil {
			defer f.onDelete(id)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.deletes[id]++
		if f.failDelete[id] {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "Internal error"})
			return
		}
		t := f.find(id)
		if t == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "Token not found"})
			return
		}
		if f.alreadyRevoked[id] && t.RevokedAt == nil {
			now := time.Now()
			t.RevokedAt = &now
		}
		if t.RevokedAt != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "token not found or already revoked"})
			return
		}
		now := time.Now()
		t.RevokedAt = &now
		writeJSON(w, http.StatusOK, map[string]string{"message": "Token revoked"})
	})
	return mux
}

type sleepRec struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleepRec) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d = append(s.d, d)
	return nil
}

func setup(t *testing.T, f *fakeAPI, pace time.Duration) (*Manager, *sleepRec) {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	m := NewManager(srv.URL, "sess-test", "run1", srv.Client(), pace)
	rec := &sleepRec{}
	m.sleep = rec.sleep
	return m, rec
}

var prof = scenario.Profile{Name: "p", Type: "proxy", Repositories: []string{"{{.RepoA}}"}, Scopes: "contents:read", Duration: "1h"}

func vars() *scenario.Vars { return scenario.PlaceholderVars() }

func TestManager_CreateSendsSessionID(t *testing.T) {
	f := newFake()
	m, _ := setup(t, f, 0)
	h, err := m.Create(context.Background(), prof, vars())
	if err != nil {
		t.Fatal(err)
	}
	if h.ID() == "" || m.Created() != 1 {
		t.Fatalf("id=%q created=%d", h.ID(), m.Created())
	}
	b := f.posts[0]
	if b["session_id"] != "scoperig-run1" || b["type"] != "proxy" || b["scopes"] != "contents:read" || b["duration"] != "1h" {
		t.Fatalf("body = %v", b)
	}
	repos, _ := b["repositories"].([]any)
	if len(repos) != 1 || strings.Contains(fmt.Sprint(repos[0]), "{{") {
		t.Fatalf("repositories not expanded: %v", repos)
	}
	if f.auth[0] != "Bearer sess-test" {
		t.Fatalf("auth = %q", f.auth[0])
	}
}

func TestManager_CreateRetries429Once(t *testing.T) {
	f := newFake()
	f.post429 = 1
	m, rec := setup(t, f, 0)
	if _, err := m.Create(context.Background(), prof, vars()); err != nil {
		t.Fatal(err)
	}
	if len(f.posts) != 2 || len(rec.d) != 1 || rec.d[0] != 60*time.Second {
		t.Fatalf("posts=%d sleeps=%v", len(f.posts), rec.d)
	}
	f.post429 = 2
	if _, err := m.Create(context.Background(), prof, vars()); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("want 429 error after one retry, got %v", err)
	}
}

func TestManager_CreateErrorRedacted(t *testing.T) {
	f := newFake()
	f.postFail = "bad token ghx_secret12345678 Authorization: Bearer sess-test"
	m, _ := setup(t, f, 0)
	_, err := m.Create(context.Background(), prof, vars())
	if err == nil {
		t.Fatal("want error")
	}
	s := err.Error()
	if strings.Contains(s, "ghx_secret") || strings.Contains(s, "sess-test") || !strings.Contains(s, "400") {
		t.Fatalf("error = %q", s)
	}
	if strings.Contains(s, "contents:read") {
		t.Fatalf("request body leaked: %q", s)
	}
}

func TestManager_SweepFallsBackAndSkipsRevoked(t *testing.T) {
	f := newFake()
	past := time.Now()
	f.toks = []*fakeTok{
		{ID: "a", SessionID: "scoperig-old", mine: true},
		{ID: "b", SessionID: "scoperig-old", mine: true, RevokedAt: &past},
		{ID: "c", SessionID: "other", mine: true},
		{ID: "d", SessionID: "scoperig-x", mine: false},
	}
	f.allFor403 = true
	m, _ := setup(t, f, 0)
	got, err := m.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "a" || f.deletes["b"] != 0 || f.deletes["c"] != 0 || f.deletes["d"] != 0 {
		t.Fatalf("revoked=%v deletes=%v", got, f.deletes)
	}

	// Admin path: ?all=true succeeds and sees other users' tokens.
	f2 := newFake()
	f2.toks = []*fakeTok{{ID: "d", SessionID: "scoperig-x"}}
	m2, _ := setup(t, f2, 0)
	got, err = m2.Sweep(context.Background())
	if err != nil || len(got) != 1 || got[0] != "d" {
		t.Fatalf("admin sweep: %v %v", got, err)
	}
}

func TestManager_RevokeAllAfterPanic(t *testing.T) {
	f := newFake()
	m, _ := setup(t, f, 0)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := m.Create(ctx, prof, vars()); err != nil {
			t.Fatal(err)
		}
	}
	func() {
		defer func() { _ = recover() }()
		defer m.RevokeAll(ctx)
		panic("x")
	}()
	if len(f.deletes) != 2 {
		t.Fatalf("deletes = %v", f.deletes)
	}
}

func TestManager_VerifyNoneLeft(t *testing.T) {
	f := newFake()
	m, _ := setup(t, f, 0)
	ctx := context.Background()
	h1, _ := m.Create(ctx, prof, vars())
	h2, _ := m.Create(ctx, prof, vars())
	if err := m.Revoke(ctx, h1.ID()); err != nil {
		t.Fatal(err)
	}
	left, err := m.VerifyNoneLeft(ctx)
	if err != nil || len(left) != 1 || left[0] != h2.ID() {
		t.Fatalf("left=%v err=%v", left, err)
	}
	if l := m.RevokeAll(ctx); len(l) != 0 {
		t.Fatalf("RevokeAll leftover %v", l)
	}
	left, err = m.VerifyNoneLeft(ctx)
	if err != nil || len(left) != 0 {
		t.Fatalf("left=%v err=%v", left, err)
	}
}

func TestManager_RevokeAllSkipsAlreadyRevoked(t *testing.T) {
	f := newFake()
	m, _ := setup(t, f, 0)
	ctx := context.Background()
	h1, _ := m.Create(ctx, prof, vars())
	h2, _ := m.Create(ctx, prof, vars())
	if err := m.Revoke(ctx, h1.ID()); err != nil {
		t.Fatal(err)
	}
	// Revoked out-of-band: server answers 400 on DELETE, GET shows revoked_at.
	f.alreadyRevoked[h2.ID()] = true
	if l := m.RevokeAll(ctx); len(l) != 0 {
		t.Fatalf("leftover %v", l)
	}
	if f.deletes[h1.ID()] != 1 {
		t.Fatalf("id1 deletes = %d", f.deletes[h1.ID()])
	}
	if l := m.RevokeAll(ctx); len(l) != 0 || f.deletes[h2.ID()] != 1 {
		t.Fatalf("second RevokeAll not idempotent: %v %v", l, f.deletes)
	}
}

func TestManager_CreateRawSharesPacer(t *testing.T) {
	f := newFake()
	m, rec := setup(t, f, 4*time.Second)
	ctx := context.Background()
	if _, err := m.Create(ctx, prof, vars()); err != nil {
		t.Fatal(err)
	}
	status, resp, err := m.CreateRaw(ctx, map[string]any{"type": "proxy", "scopes": "contents:read"})
	if err != nil || status != http.StatusCreated {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if _, ok := resp["token"]; ok {
		t.Fatal("CreateRaw must strip token")
	}
	if f.posts[1]["session_id"] != "scoperig-run1" {
		t.Fatalf("raw body session_id = %v", f.posts[1]["session_id"])
	}
	if len(rec.d) != 1 || rec.d[0] != 4*time.Second {
		t.Fatalf("sleeps = %v", rec.d)
	}
	if m.Created() != 2 {
		t.Fatalf("created = %d", m.Created())
	}
}

func TestManager_RevokeAllWaitsForInFlightCreate(t *testing.T) {
	f := newFake()
	arrived := make(chan struct{})
	release := make(chan struct{})
	f.onPost = func() { close(arrived); <-release }
	m, _ := setup(t, f, 0)
	ctx := context.Background()
	created := make(chan error, 1)
	go func() { _, err := m.Create(ctx, prof, vars()); created <- err }()
	<-arrived
	done := make(chan []string, 1)
	go func() { done <- m.RevokeAll(ctx) }()
	time.Sleep(20 * time.Millisecond) // let RevokeAll reach its barrier
	close(release)
	if err := <-created; err != nil {
		t.Fatalf("create: %v", err)
	}
	if left := <-done; len(left) != 0 {
		t.Fatalf("leftover %v", left)
	}
	if len(f.deletes) != 1 {
		t.Fatalf("in-flight token not revoked: %v", f.deletes)
	}
	f.onPost = nil
	if _, err := m.Create(ctx, prof, vars()); !errors.Is(err, ErrClosed) {
		t.Fatalf("create after close: %v", err)
	}
}

func TestManager_VerifyNoneLeftFailsClosed(t *testing.T) {
	f := newFake()
	m, _ := setup(t, f, 0)
	ctx := context.Background()
	h1, _ := m.Create(ctx, prof, vars())
	h2, _ := m.Create(ctx, prof, vars())
	if err := m.Revoke(ctx, h2.ID()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.find(h1.ID()).hidden = true // unrevoked, absent from list
	f.find(h2.ID()).hidden = true // revoked, absent from list
	f.mu.Unlock()
	left, err := m.VerifyNoneLeft(ctx)
	if err != nil || len(left) != 1 || left[0] != h1.ID() {
		t.Fatalf("left=%v err=%v", left, err)
	}
}

func TestManager_RevokeAllErrReportsReasons(t *testing.T) {
	f := newFake()
	m, _ := setup(t, f, 0)
	ctx := context.Background()
	h1, _ := m.Create(ctx, prof, vars())
	h2, _ := m.Create(ctx, prof, vars())
	f.failDelete[h1.ID()] = true
	left, err := m.RevokeAllErr(ctx)
	if len(left) != 1 || left[0] != h1.ID() || err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("left=%v err=%v", left, err)
	}
	if f.deletes[h2.ID()] != 1 {
		t.Fatalf("h2 not revoked")
	}
}

func TestManager_RevokeAllSurvivesCancelMidLoop(t *testing.T) {
	f := newFake()
	m, _ := setup(t, f, 0)
	ctx, cancel := context.WithCancel(context.Background())
	for i := 0; i < 3; i++ {
		if _, err := m.Create(ctx, prof, vars()); err != nil {
			t.Fatal(err)
		}
	}
	f.onDelete = func(string) { cancel() }
	if left := m.RevokeAll(ctx); len(left) != 0 {
		t.Fatalf("leftover %v", left)
	}
	if len(f.deletes) != 3 {
		t.Fatalf("deletes = %v", f.deletes)
	}
}

func TestManager_SweepSessionMatchesExactSessionOnly(t *testing.T) {
	f := newFake()
	m, _ := setup(t, f, 0)
	f.toks = []*fakeTok{
		{ID: "mine", SessionID: m.SessionID()},
		{ID: "other-run", SessionID: m.SessionID() + "x"},
		{ID: "old", SessionID: "scoperig-old"},
	}
	got, failed, err := m.SweepSession(context.Background())
	if err != nil || len(failed) != 0 || len(got) != 1 || got[0] != "mine" {
		t.Fatalf("revoked=%v failed=%v err=%v", got, failed, err)
	}
	if f.deletes["other-run"] != 0 || f.deletes["old"] != 0 {
		t.Fatalf("deletes=%v", f.deletes)
	}
}

func TestManager_CreateRawOverwritesSessionID(t *testing.T) {
	f := newFake()
	m, _ := setup(t, f, 0)
	body := map[string]any{"type": "proxy", "scopes": "contents:read", "session_id": "evil"}
	if _, _, err := m.CreateRaw(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	if f.posts[0]["session_id"] != "scoperig-run1" {
		t.Fatalf("sent session_id = %v, want scoperig-run1", f.posts[0]["session_id"])
	}
	if body["session_id"] != "evil" {
		t.Fatal("CreateRaw must not modify the caller's body")
	}
}
