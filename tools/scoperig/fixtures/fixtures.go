// Package fixtures discovers and seeds the scoperig fixture repositories.
// Every request goes through GHP with a caller-supplied token; this package
// never creates tokens and never talks to GitHub directly.
package fixtures

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/goodtune/ghp/tools/scoperig/redact"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

// API is a thin client that sends REST requests through GHP (/api/v3) with a token.
type API interface {
	Do(ctx context.Context, method, path string, body any) (status int, resp []byte, err error)
}

// Fixed fixture names. Seeding is keyed by these values.
const (
	Label       = "scoperig"
	IssueTitle  = "scoperig fixture issue"
	Branch      = "scoperig-fixture"
	PRTitle     = "scoperig fixture PR"
	ReleaseTag  = "scoperig-fixture-v0"
	FixtureFile = "fixture.txt"
)

// maxResponse bounds the size of a response body read by HTTPAPI.
const maxResponse = 8 << 20

// HTTPAPI implements API over net/http. BaseURL is the REST root, for
// example "https://ghp.example/api/v3".
type HTTPAPI struct {
	Client  *http.Client
	BaseURL string
	token   string
}

// NewHTTPAPI returns an API that sends "Authorization: Bearer <token>".
func NewHTTPAPI(c *http.Client, baseURL, token string) *HTTPAPI {
	if c == nil {
		c = http.DefaultClient
	}
	return &HTTPAPI{Client: c, BaseURL: strings.TrimRight(baseURL, "/"), token: token}
}

// Do sends one request. A JSON body is encoded when body is non-nil.
func (a *HTTPAPI) Do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("encode %s %s: %w", method, path, err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.BaseURL+path, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("%s %s: read body: %w", method, path, err)
	}
	return resp.StatusCode, b, nil
}

// Plan lists what Ensure did, or would do, in human-readable form.
type Plan struct {
	Repo   string
	Create bool
	Seed   []string
}

var allSeeds = []string{
	"create label " + Label,
	"create issue " + strconv.Quote(IssueTitle),
	"create branch " + Branch,
	"commit " + FixtureFile + " to " + Branch,
	"open PR " + strconv.Quote(PRTitle),
	"create release " + ReleaseTag,
}

func splitRepo(repo string) (owner, name string, err error) {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", "", fmt.Errorf("invalid repo %q: want owner/name", repo)
	}
	return owner, name, nil
}

func missing(what, repo string) error {
	return fmt.Errorf("fixture %s missing in %s; run 'scoperig fixtures ensure'", what, repo)
}

// getJSON performs a GET. It returns found=false on 404 and an error on any
// other non-200 status.
func getJSON(ctx context.Context, api API, path string, out any) (bool, error) {
	st, b, err := api.Do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false, err
	}
	if st == http.StatusNotFound {
		return false, nil
	}
	if st != http.StatusOK {
		return false, statusErr(http.MethodGet, path, st, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return false, fmt.Errorf("GET %s: decode: %w", path, err)
		}
	}
	return true, nil
}

func send(ctx context.Context, api API, method, path string, body, out any) error {
	st, b, err := api.Do(ctx, method, path, body)
	if err != nil {
		return err
	}
	if st < 200 || st > 299 {
		return statusErr(method, path, st, b)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("%s %s: decode: %w", method, path, err)
		}
	}
	return nil
}

type repoInfo struct {
	ID            int64  `json:"id"`
	DefaultBranch string `json:"default_branch"`
}

type numbered struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
}

func repoPath(repo string) string {
	owner, name, _ := splitRepo(repo)
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name)
}

func findIssue(ctx context.Context, api API, repo string) (int, error) {
	var list []numbered
	p := repoPath(repo) + "/issues?labels=" + url.QueryEscape(Label) + "&state=open&per_page=100"
	ok, err := getJSON(ctx, api, p, &list)
	if err != nil || !ok {
		return 0, err
	}
	for _, i := range list {
		if i.Title == IssueTitle {
			return i.Number, nil
		}
	}
	return 0, nil
}

func findPR(ctx context.Context, api API, repo, owner string) (int, error) {
	var list []numbered
	p := repoPath(repo) + "/pulls?head=" + url.QueryEscape(owner+":"+Branch) + "&state=open"
	ok, err := getJSON(ctx, api, p, &list)
	if err != nil || !ok {
		return 0, err
	}
	for _, pr := range list {
		if pr.Title == PRTitle {
			return pr.Number, nil
		}
	}
	return 0, nil
}

func findRelease(ctx context.Context, api API, repo string) (int64, error) {
	var rel struct {
		ID int64 `json:"id"`
	}
	ok, err := getJSON(ctx, api, repoPath(repo)+"/releases/tags/"+url.PathEscape(ReleaseTag), &rel)
	if err != nil || !ok {
		return 0, err
	}
	return rel.ID, nil
}

// Discover reads the fixture values from repo. Any missing piece is an error
// that tells the operator to run 'scoperig fixtures ensure'.
func Discover(ctx context.Context, api API, repo string) (scenario.RepoRef, scenario.FixtureVals, error) {
	owner, name, err := splitRepo(repo)
	if err != nil {
		return scenario.RepoRef{}, scenario.FixtureVals{}, err
	}
	var ri repoInfo
	ok, err := getJSON(ctx, api, repoPath(repo), &ri)
	if err != nil {
		return scenario.RepoRef{}, scenario.FixtureVals{}, err
	}
	if !ok {
		return scenario.RepoRef{}, scenario.FixtureVals{}, missing("repo", repo)
	}
	ref := scenario.RepoRef{Owner: owner, Name: name, ID: ri.ID}
	v := scenario.FixtureVals{Branch: Branch, Label: Label, PRTitle: PRTitle, IssueTitle: IssueTitle, ReleaseTag: ReleaseTag}
	if v.IssueNumber, err = findIssue(ctx, api, repo); err != nil {
		return ref, v, err
	}
	if v.IssueNumber == 0 {
		return ref, v, missing("issue", repo)
	}
	if v.PRNumber, err = findPR(ctx, api, repo, owner); err != nil {
		return ref, v, err
	}
	if v.PRNumber == 0 {
		return ref, v, missing("pr", repo)
	}
	if v.ReleaseID, err = findRelease(ctx, api, repo); err != nil {
		return ref, v, err
	}
	if v.ReleaseID == 0 {
		return ref, v, missing("release", repo)
	}
	return ref, v, nil
}

// maxErrBody bounds how much of a response body is quoted in an error.
const maxErrBody = 512

// statusErr builds an error for an unexpected status, quoting up to
// maxErrBody bytes of the redacted response body to help diagnosis.
func statusErr(method, path string, st int, body []byte) error {
	if len(body) > maxErrBody {
		body = body[:maxErrBody]
	}
	msg := strings.TrimSpace(redact.String(string(body)))
	if msg == "" {
		return fmt.Errorf("%s %s: status %d", method, path, st)
	}
	return fmt.Errorf("%s %s: status %d: %s", method, path, st, msg)
}

// CheckSafe enforces the safety guard: the repo name must contain
// "scoperig" (matched case-insensitively) and its owner must equal the
// probed login (also case-insensitive, as GitHub logins are).
func CheckSafe(repo, login string) error {
	owner, name, err := splitRepo(repo)
	if err != nil {
		return fmt.Errorf("refusing to touch %q: %w", repo, err)
	}
	if !strings.Contains(strings.ToLower(name), "scoperig") {
		return fmt.Errorf("refusing to touch %s: repo name must contain \"scoperig\"", repo)
	}
	if login == "" || !strings.EqualFold(owner, login) {
		return fmt.Errorf("refusing to touch %s: owner must equal the token's login %q", repo, login)
	}
	return nil
}

// Ensure makes repo exist (when create and canCreate) and seeds every fixture
// object that is missing. Each step checks for the object first, so a second
// run makes no changes. It refuses, with no non-GET call, any repo that
// fails the safety guard.
func Ensure(ctx context.Context, api API, repo, login string, create, canCreate bool) (Plan, error) {
	plan := Plan{Repo: repo}
	if err := CheckSafe(repo, login); err != nil {
		return plan, err
	}
	owner, name, _ := splitRepo(repo)
	rp := repoPath(repo)

	var ri repoInfo
	ok, err := getJSON(ctx, api, rp, &ri)
	if err != nil {
		return plan, err
	}
	if !ok {
		plan.Create = true
		plan.Seed = append([]string(nil), allSeeds...)
		if !create {
			return plan, fmt.Errorf("would create %s; pass --create-fixtures", repo)
		}
		if !canCreate {
			return plan, fmt.Errorf("cannot create %s: the token lacks the repo_create capability; "+
				"create the private repo by hand or with 'gh repo create --private %s' under your own login, "+
				"then re-run 'scoperig fixtures ensure' to seed", repo, repo)
		}
		plan.Seed = nil
		body := map[string]any{"name": name, "private": true, "auto_init": true}
		if err := send(ctx, api, http.MethodPost, "/user/repos", body, nil); err != nil {
			return plan, fmt.Errorf("create %s: %w", repo, err)
		}
		if ok, err = getJSON(ctx, api, rp, &ri); err != nil {
			return plan, err
		} else if !ok {
			return plan, fmt.Errorf("created %s but it is not visible yet; re-run", repo)
		}
	}
	if ri.DefaultBranch == "" {
		return plan, fmt.Errorf("%s: no default branch", repo)
	}
	add := func(s string) { plan.Seed = append(plan.Seed, s) }

	// Label.
	if ok, err := getJSON(ctx, api, rp+"/labels/"+url.PathEscape(Label), nil); err != nil {
		return plan, err
	} else if !ok {
		if err := send(ctx, api, http.MethodPost, rp+"/labels",
			map[string]any{"name": Label, "color": "5319e7"}, nil); err != nil {
			return plan, err
		}
		add(allSeeds[0])
	}

	// Issue.
	if n, err := findIssue(ctx, api, repo); err != nil {
		return plan, err
	} else if n == 0 {
		if err := send(ctx, api, http.MethodPost, rp+"/issues",
			map[string]any{"title": IssueTitle, "labels": []string{Label}}, nil); err != nil {
			return plan, err
		}
		add(allSeeds[1])
	}

	// A repo created by hand (gh repo create --private) has no commits and
	// GitHub answers git ref reads with 409. Make an initial commit on the
	// default branch so the branch, PR and release can be seeded.
	if st, b, err := api.Do(ctx, http.MethodGet, rp+"/git/ref/heads/"+url.PathEscape(ri.DefaultBranch), nil); err != nil {
		return plan, err
	} else if st == http.StatusConflict {
		body := map[string]any{
			"message": "scoperig initial commit",
			"content": base64.StdEncoding.EncodeToString([]byte("# " + name + "\n\nFixture repository for the GHP scope regression rig.\n")),
		}
		if err := send(ctx, api, http.MethodPut, rp+"/contents/README.md", body, nil); err != nil {
			return plan, fmt.Errorf("initial commit: %w", err)
		}
		add("initial commit README.md on " + ri.DefaultBranch)
	} else if st != http.StatusOK && st != http.StatusNotFound {
		return plan, statusErr(http.MethodGet, rp+"/git/ref/heads/"+ri.DefaultBranch, st, b)
	}

	// Branch from the default branch head.
	if ok, err := getJSON(ctx, api, rp+"/git/ref/heads/"+Branch, nil); err != nil {
		return plan, err
	} else if !ok {
		var head struct {
			Object struct {
				SHA string `json:"sha"`
			} `json:"object"`
		}
		if ok, err := getJSON(ctx, api, rp+"/git/ref/heads/"+ri.DefaultBranch, &head); err != nil {
			return plan, err
		} else if !ok || head.Object.SHA == "" {
			return plan, fmt.Errorf("%s: default branch %s has no head", repo, ri.DefaultBranch)
		}
		if err := send(ctx, api, http.MethodPost, rp+"/git/refs",
			map[string]any{"ref": "refs/heads/" + Branch, "sha": head.Object.SHA}, nil); err != nil {
			return plan, err
		}
		add(allSeeds[2])
	}

	// Fixture file on the branch.
	if ok, err := getJSON(ctx, api, rp+"/contents/"+FixtureFile+"?ref="+url.QueryEscape(Branch), nil); err != nil {
		return plan, err
	} else if !ok {
		body := map[string]any{
			"message": "scoperig fixture",
			"content": base64.StdEncoding.EncodeToString([]byte("scoperig fixture\n")),
			"branch":  Branch,
		}
		if err := send(ctx, api, http.MethodPut, rp+"/contents/"+FixtureFile, body, nil); err != nil {
			return plan, err
		}
		add(allSeeds[3])
	}

	// Pull request.
	if n, err := findPR(ctx, api, repo, owner); err != nil {
		return plan, err
	} else if n == 0 {
		body := map[string]any{"title": PRTitle, "head": Branch, "base": ri.DefaultBranch,
			"body": "Fixture PR for the scope regression rig. Do not merge."}
		if err := send(ctx, api, http.MethodPost, rp+"/pulls", body, nil); err != nil {
			return plan, err
		}
		add(allSeeds[4])
	}

	// Release on the default branch.
	if id, err := findRelease(ctx, api, repo); err != nil {
		return plan, err
	} else if id == 0 {
		body := map[string]any{"tag_name": ReleaseTag, "target_commitish": ri.DefaultBranch, "name": ReleaseTag}
		if err := send(ctx, api, http.MethodPost, rp+"/releases", body, nil); err != nil {
			return plan, err
		}
		add(allSeeds[5])
	}
	return plan, nil
}
