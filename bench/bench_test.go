//go:build bench

package bench_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// repoConfig defines a repository to benchmark and how many warm-cache
// iterations to run. Larger repos use fewer runs to keep total wall time
// reasonable.
type repoConfig struct {
	Repo           string
	WarmRuns       int
	TimeoutSeconds int // 0 = use server default (30s)
}

// defaultRepos is the standard set of repositories exercised by the benchmark.
// django/django is a medium repo (~450 MB, 20 years of history).
// torvalds/linux is a huge repo (~4.5 GB, the largest public repo on GitHub).
var defaultRepos = []repoConfig{
	{"django/django", 10, 0},
	{"torvalds/linux", 3, 600},
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func repoSlug(repo string) string {
	return strings.ReplaceAll(repo, "/", "-")
}

// percentile returns the p-th percentile of a sorted slice using linear interpolation.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	k := float64(len(sorted)-1) * p / 100
	f := math.Floor(k)
	c := math.Ceil(k)
	if f == c {
		return sorted[int(k)]
	}
	return sorted[int(f)]*(c-k) + sorted[int(c)]*(k-f)
}

func overheadPct(value, baseline float64) string {
	if baseline <= 0 {
		return "N/A"
	}
	return fmt.Sprintf("%+.1f%%", (value-baseline)/baseline*100)
}

func round3(v float64) float64 { return math.Round(v*1000) / 1000 }

// measureClone runs git clone, captures stderr to a log file, and returns
// the wall-clock duration. The cloned directory is removed immediately after
// timing to conserve disk space. Returns an error if the clone fails rather
// than calling t.Fatal, so callers can report partial results.
func measureClone(t *testing.T, label, logsDir string, verbose bool, args ...string) (time.Duration, error) {
	t.Helper()

	cloneDir, err := os.MkdirTemp("", "bench-clone-*")
	if err != nil {
		return 0, fmt.Errorf("create temp dir for %s: %w", label, err)
	}
	defer os.RemoveAll(cloneDir)

	target := filepath.Join(cloneDir, label)
	gitArgs := append([]string{"clone"}, args...)
	gitArgs = append(gitArgs, target)

	cmd := exec.Command("git", gitArgs...)
	if verbose {
		cmd.Env = append(os.Environ(), "GIT_CURL_VERBOSE=1")
	}

	logFile, err := os.Create(filepath.Join(logsDir, label+"-stderr.log"))
	if err != nil {
		return 0, fmt.Errorf("create log for %s: %w", label, err)
	}
	defer logFile.Close()
	cmd.Stderr = logFile

	start := time.Now()
	if err := cmd.Run(); err != nil {
		return time.Since(start), fmt.Errorf("git clone %s: %w", label, err)
	}
	return time.Since(start), nil
}

// adminClient logs in via the dev-mode test-login endpoint and returns
// an *http.Client with the session cookie set.
func adminClient(t *testing.T, baseURL string) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	client := &http.Client{Jar: jar}

	resp, err := client.Post(
		baseURL+"/auth/test-login",
		"application/json",
		strings.NewReader(`{"username":"bench","role":"admin"}`),
	)
	if err != nil {
		t.Fatalf("test-login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test-login returned %d", resp.StatusCode)
	}
	return client
}

// registerCachedRepo registers a repository for git caching via the admin API.
// timeoutSeconds of 0 means use the server default.
func registerCachedRepo(t *testing.T, client *http.Client, baseURL, repo string, timeoutSeconds int) {
	t.Helper()

	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		t.Fatalf("invalid repo %q, expected owner/name", repo)
	}

	var body string
	if timeoutSeconds > 0 {
		body = fmt.Sprintf(`{"owner":%q,"name":%q,"enabled":true,"timeout_seconds":%d}`, parts[0], parts[1], timeoutSeconds)
	} else {
		body = fmt.Sprintf(`{"owner":%q,"name":%q,"enabled":true}`, parts[0], parts[1])
	}
	resp, err := client.Post(baseURL+"/api/cached-repos", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("register cached repo %s: %v", repo, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		t.Fatalf("register cached repo %s returned %d", repo, resp.StatusCode)
	}
	t.Logf("Registered %s for caching (HTTP %d)", repo, resp.StatusCode)
}

type repoResults struct {
	Repo      string         `json:"repo"`
	Timestamp string         `json:"timestamp"`
	Direct    scenarioResult `json:"direct"`
	ColdCache scenarioResult `json:"cold_cache"`
	WarmCache warmResult     `json:"warm_cache"`
}

type scenarioResult struct {
	DurationSeconds float64 `json:"duration_seconds"`
}

type warmResult struct {
	Runs  []float64 `json:"runs"`
	Count int       `json:"count"`
	Min   float64   `json:"min"`
	Max   float64   `json:"max"`
	Mean  float64   `json:"mean"`
	P50   float64   `json:"p50"`
	P80   float64   `json:"p80"`
	P95   float64   `json:"p95"`
}

// benchmarkRepo runs the full direct/cold/warm benchmark for a single
// repository and returns the computed results.
func benchmarkRepo(t *testing.T, rc repoConfig, baseURL, resultsDir string) *repoResults {
	t.Helper()

	slug := repoSlug(rc.Repo)
	logsDir := filepath.Join(resultsDir, "logs", slug)
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		t.Fatalf("create logs dir: %v", err)
	}

	cloneURL := fmt.Sprintf("%s/%s.git", baseURL, rc.Repo)

	// Direct clone (baseline).
	t.Log("--- Direct clone ---")
	directTime, err := measureClone(t, "direct", logsDir, false,
		fmt.Sprintf("https://github.com/%s.git", rc.Repo))
	if err != nil {
		t.Fatalf("direct clone failed, cannot continue: %v", err)
	}
	t.Logf("  Duration: %.3fs", directTime.Seconds())

	// Cold cache clone (first request through GHP).
	t.Log("--- GHP cold cache clone ---")
	coldTime, err := measureClone(t, "cold-cache", logsDir, true,
		"-c", "http.extraHeader=Host: github.com", cloneURL)
	if err != nil {
		t.Logf("WARNING: cold cache clone failed (check stderr log): %v", err)
	} else {
		t.Logf("  Duration: %.3fs", coldTime.Seconds())
	}

	// Warm cache clones — skip if cold cache failed (cache not populated).
	var warmTimes []time.Duration
	if err == nil {
		t.Logf("--- GHP warm cache clones (%d runs) ---", rc.WarmRuns)
		warmTimes = make([]time.Duration, 0, rc.WarmRuns)
		for i := range rc.WarmRuns {
			label := fmt.Sprintf("warm-cache-%02d", i+1)
			d, werr := measureClone(t, label, logsDir, true,
				"-c", "http.extraHeader=Host: github.com", cloneURL)
			if werr != nil {
				t.Logf("WARNING: warm cache run %d failed: %v", i+1, werr)
				continue
			}
			warmTimes = append(warmTimes, d)
			t.Logf("  Run %2d: %.3fs", i+1, d.Seconds())
		}
	} else {
		t.Log("--- Skipping warm cache clones (cold cache failed) ---")
	}

	// Compute stats.
	res := &repoResults{
		Repo:      rc.Repo,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Direct:    scenarioResult{DurationSeconds: round3(directTime.Seconds())},
		ColdCache: scenarioResult{DurationSeconds: round3(coldTime.Seconds())},
	}

	if len(warmTimes) > 0 {
		warmSec := make([]float64, len(warmTimes))
		for i, d := range warmTimes {
			warmSec[i] = d.Seconds()
		}
		sorted := make([]float64, len(warmSec))
		copy(sorted, warmSec)
		sort.Float64s(sorted)

		var sum float64
		for _, v := range sorted {
			sum += v
		}
		mean := sum / float64(len(sorted))

		res.WarmCache = warmResult{
			Runs:  warmSec,
			Count: len(warmSec),
			Min:   round3(sorted[0]),
			Max:   round3(sorted[len(sorted)-1]),
			Mean:  round3(mean),
			P50:   round3(percentile(sorted, 50)),
			P80:   round3(percentile(sorted, 80)),
			P95:   round3(percentile(sorted, 95)),
		}
	}

	// Write per-repo JSON.
	jsonData, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}
	jsonPath := filepath.Join(resultsDir, fmt.Sprintf("results-%s.json", slug))
	if err := os.WriteFile(jsonPath, append(jsonData, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", jsonPath, err)
	}

	return res
}

func TestCachePerformance(t *testing.T) {
	image := envOr("GHP_IMAGE", "ghcr.io/goodtune/ghp:latest")
	resultsDir := envOr("RESULTS_DIR", "results")

	// Allow single-repo override via REPO env var.
	repos := defaultRepos
	if r := os.Getenv("REPO"); r != "" {
		repos = []repoConfig{{r, envInt("WARM_RUNS", 10), envInt("TIMEOUT_SECONDS", 0)}}
	}

	if err := os.MkdirAll(filepath.Join(resultsDir, "logs"), 0o755); err != nil {
		t.Fatalf("create results dir: %v", err)
	}

	ctx := context.Background()

	t.Logf("Starting GHP container (image: %s)", image)
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        image,
			Cmd:          []string{"serve", "--migrate"},
			ExposedPorts: []string{"8080/tcp", "9136/tcp"},
			Env: map[string]string{
				"GHP_DEV_MODE":             "true",
				"GHP_DATABASE_DRIVER":      "sqlite",
				"GHP_DATABASE_DSN":         "/tmp/ghp.db",
				"GHP_ENCRYPTION_KEY":       "0000000000000000000000000000000000000000000000000000000000000000",
				"GHP_SERVER_LISTEN":        ":8080",
				"GHP_METRICS_LISTEN":       ":9136",
				"GHP_LOGGING_LEVEL":        "debug",
				"GHP_GITHUB_CLIENT_ID":     "unused",
				"GHP_GITHUB_CLIENT_SECRET": "unused",
				"GHP_CACHE_ENABLED":        "true",
				"GHP_CACHE_STORAGE_PATH":   "/tmp/cache",
			},
			WaitingFor: wait.ForHTTP("/auth/status").
				WithPort("8080/tcp").
				WithStartupTimeout(60 * time.Second).
				WithStatusCodeMatcher(func(status int) bool {
					return status < 500
				}),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start GHP container: %v", err)
	}
	t.Cleanup(func() {
		logsDir := filepath.Join(resultsDir, "logs")
		if logReader, err := container.Logs(ctx); err == nil {
			logBytes, _ := io.ReadAll(logReader)
			logReader.Close()
			_ = os.WriteFile(filepath.Join(logsDir, "container.log"), logBytes, 0o644)
		}
		_ = container.Terminate(ctx)
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("container port: %v", err)
	}
	baseURL := fmt.Sprintf("http://%s:%s", host, port.Port())
	t.Logf("GHP available at %s", baseURL)

	// Authenticate once and register all repos for caching.
	client := adminClient(t, baseURL)
	for _, rc := range repos {
		registerCachedRepo(t, client, baseURL, rc.Repo, rc.TimeoutSeconds)
	}

	// Run per-repo benchmarks as subtests.
	allResults := make([]*repoResults, 0, len(repos))
	for _, rc := range repos {
		rc := rc
		t.Run(repoSlug(rc.Repo), func(t *testing.T) {
			res := benchmarkRepo(t, rc, baseURL, resultsDir)
			allResults = append(allResults, res)
		})
	}

	// Write combined report.
	writeReport(t, resultsDir, allResults)
}

func writeReport(t *testing.T, resultsDir string, all []*repoResults) {
	t.Helper()

	if len(all) == 0 {
		t.Log("No results to report.")
		return
	}

	// Write combined JSON.
	jsonData, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		t.Fatalf("marshal combined results: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultsDir, "results.json"), append(jsonData, '\n'), 0o644); err != nil {
		t.Fatalf("write results.json: %v", err)
	}

	// Build markdown report.
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "## Git Clone Cache Performance Results\n\n")
	fmt.Fprintf(&buf, "**Date:** %s\n\n", all[0].Timestamp)

	for _, res := range all {
		directSec := res.Direct.DurationSeconds
		coldSec := res.ColdCache.DurationSeconds
		w := res.WarmCache

		fmt.Fprintf(&buf, "### `%s`\n\n", res.Repo)
		fmt.Fprintf(&buf, "| Scenario | Duration | vs Direct |\n")
		fmt.Fprintf(&buf, "|----------|----------|-----------|\n")
		fmt.Fprintf(&buf, "| Direct clone | %.2fs | -- |\n", directSec)
		if coldSec > 0 {
			fmt.Fprintf(&buf, "| GHP -- cold cache | %.2fs | %s |\n", coldSec, overheadPct(coldSec, directSec))
		} else {
			fmt.Fprintf(&buf, "| GHP -- cold cache | FAILED | -- |\n")
		}
		if w.Count > 0 {
			fmt.Fprintf(&buf, "| GHP -- warm cache (p50) | %.2fs | %s |\n", w.P50, overheadPct(w.P50, directSec))
			fmt.Fprintf(&buf, "| GHP -- warm cache (p80) | %.2fs | %s |\n", w.P80, overheadPct(w.P80, directSec))
			fmt.Fprintf(&buf, "| GHP -- warm cache (p95) | %.2fs | %s |\n", w.P95, overheadPct(w.P95, directSec))
		}
		fmt.Fprintf(&buf, "\n")

		if w.Count > 0 {
			fmt.Fprintf(&buf, "**Warm cache distribution** (%d runs): ", w.Count)
			fmt.Fprintf(&buf, "min %.2fs, mean %.2fs, max %.2fs\n\n", w.Min, w.Mean, w.Max)

			fmt.Fprintf(&buf, "<details>\n<summary>Individual runs</summary>\n\n")
			fmt.Fprintf(&buf, "| Run | Duration | vs Direct |\n")
			fmt.Fprintf(&buf, "|----:|----------|-----------|\n")
			for i, v := range w.Runs {
				fmt.Fprintf(&buf, "| %d | %.2fs | %s |\n", i+1, v, overheadPct(v, directSec))
			}
			fmt.Fprintf(&buf, "\n</details>\n\n")
		} else if coldSec == 0 {
			fmt.Fprintf(&buf, "> Cold cache clone failed — warm cache runs skipped. Check stderr logs for details.\n\n")
		}
		fmt.Fprintf(&buf, "---\n\n")
	}

	report := buf.String()

	if err := os.WriteFile(filepath.Join(resultsDir, "report.md"), []byte(report), 0o644); err != nil {
		t.Fatalf("write report.md: %v", err)
	}

	t.Log("\n" + report)

	if summaryFile := os.Getenv("GITHUB_STEP_SUMMARY"); summaryFile != "" {
		if f, err := os.OpenFile(summaryFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644); err == nil {
			f.WriteString(report)
			f.Close()
		}
	}
}
