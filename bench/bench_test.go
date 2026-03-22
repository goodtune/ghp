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

// measureClone runs git clone, captures stderr to a log file, and returns
// the wall-clock duration. The cloned directory is removed immediately after
// timing to conserve disk space.
func measureClone(t *testing.T, label, logsDir string, verbose bool, args ...string) time.Duration {
	t.Helper()

	cloneDir, err := os.MkdirTemp("", "bench-clone-*")
	if err != nil {
		t.Fatalf("create temp dir for %s: %v", label, err)
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
		t.Fatalf("create log for %s: %v", label, err)
	}
	defer logFile.Close()
	cmd.Stderr = logFile

	start := time.Now()
	if err := cmd.Run(); err != nil {
		t.Fatalf("git clone %s: %v", label, err)
	}
	return time.Since(start)
}

// registerCachedRepo logs in via the dev-mode test-login endpoint and
// registers the given repository for git caching.
func registerCachedRepo(t *testing.T, baseURL, repo string) {
	t.Helper()

	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		t.Fatalf("invalid repo %q, expected owner/name", repo)
	}
	owner, name := parts[0], parts[1]

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

	body := fmt.Sprintf(`{"owner":%q,"name":%q,"enabled":true}`, owner, name)
	resp, err = client.Post(baseURL+"/api/cached-repos", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("register cached repo: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		t.Fatalf("register cached repo returned %d", resp.StatusCode)
	}
	t.Logf("Registered %s/%s for caching (HTTP %d)", owner, name, resp.StatusCode)
}

type results struct {
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

func TestCachePerformance(t *testing.T) {
	image := envOr("GHP_IMAGE", "ghcr.io/goodtune/ghp:latest")
	repo := envOr("REPO", "django/django")
	warmRuns := envInt("WARM_RUNS", 10)
	resultsDir := envOr("RESULTS_DIR", "results")
	logsDir := filepath.Join(resultsDir, "logs")

	if err := os.MkdirAll(logsDir, 0o755); err != nil {
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
				WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start GHP container: %v", err)
	}
	t.Cleanup(func() {
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

	registerCachedRepo(t, baseURL, repo)

	cloneURL := fmt.Sprintf("%s/%s.git", baseURL, repo)

	// Direct clone (baseline).
	t.Log("--- Direct clone ---")
	directTime := measureClone(t, "direct", logsDir, false,
		fmt.Sprintf("https://github.com/%s.git", repo))
	t.Logf("  Duration: %.3fs", directTime.Seconds())

	// Cold cache clone (first request through GHP).
	t.Log("--- GHP cold cache clone ---")
	coldTime := measureClone(t, "cold-cache", logsDir, true,
		"-c", "http.extraHeader=Host: github.com", cloneURL)
	t.Logf("  Duration: %.3fs", coldTime.Seconds())

	// Warm cache clones.
	t.Logf("--- GHP warm cache clones (%d runs) ---", warmRuns)
	warmTimes := make([]time.Duration, warmRuns)
	for i := range warmRuns {
		label := fmt.Sprintf("warm-cache-%02d", i+1)
		warmTimes[i] = measureClone(t, label, logsDir, true,
			"-c", "http.extraHeader=Host: github.com", cloneURL)
		t.Logf("  Run %2d: %.3fs", i+1, warmTimes[i].Seconds())
	}

	writeResults(t, resultsDir, repo, directTime, coldTime, warmTimes)
}

func round3(v float64) float64 { return math.Round(v*1000) / 1000 }

func writeResults(t *testing.T, resultsDir, repo string, direct, cold time.Duration, warm []time.Duration) {
	t.Helper()

	warmSec := make([]float64, len(warm))
	for i, d := range warm {
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
	p50 := percentile(sorted, 50)
	p80 := percentile(sorted, 80)
	p95 := percentile(sorted, 95)

	res := results{
		Repo:      repo,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Direct:    scenarioResult{DurationSeconds: round3(direct.Seconds())},
		ColdCache: scenarioResult{DurationSeconds: round3(cold.Seconds())},
		WarmCache: warmResult{
			Runs:  warmSec,
			Count: len(warmSec),
			Min:   round3(sorted[0]),
			Max:   round3(sorted[len(sorted)-1]),
			Mean:  round3(mean),
			P50:   round3(p50),
			P80:   round3(p80),
			P95:   round3(p95),
		},
	}

	jsonData, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}
	if err := os.WriteFile(filepath.Join(resultsDir, "results.json"), append(jsonData, '\n'), 0o644); err != nil {
		t.Fatalf("write results.json: %v", err)
	}

	// Build markdown report.
	directSec := direct.Seconds()
	coldSec := cold.Seconds()

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "## Git Clone Cache Performance Results\n\n")
	fmt.Fprintf(&buf, "**Repository:** `%s`\n", repo)
	fmt.Fprintf(&buf, "**Date:** %s\n\n", res.Timestamp)
	fmt.Fprintf(&buf, "### Summary\n\n")
	fmt.Fprintf(&buf, "| Scenario | Duration | vs Direct |\n")
	fmt.Fprintf(&buf, "|----------|----------|-----------|\n")
	fmt.Fprintf(&buf, "| Direct clone | %.2fs | -- |\n", directSec)
	fmt.Fprintf(&buf, "| GHP -- cold cache | %.2fs | %s |\n", coldSec, overheadPct(coldSec, directSec))
	fmt.Fprintf(&buf, "| GHP -- warm cache (p50) | %.2fs | %s |\n", p50, overheadPct(p50, directSec))
	fmt.Fprintf(&buf, "| GHP -- warm cache (p80) | %.2fs | %s |\n", p80, overheadPct(p80, directSec))
	fmt.Fprintf(&buf, "| GHP -- warm cache (p95) | %.2fs | %s |\n\n", p95, overheadPct(p95, directSec))
	fmt.Fprintf(&buf, "### Warm Cache Distribution (%d runs)\n\n", len(warmSec))
	fmt.Fprintf(&buf, "| Stat | Value |\n")
	fmt.Fprintf(&buf, "|------|-------|\n")
	fmt.Fprintf(&buf, "| Min | %.2fs |\n", sorted[0])
	fmt.Fprintf(&buf, "| Mean | %.2fs |\n", mean)
	fmt.Fprintf(&buf, "| p50 | %.2fs |\n", p50)
	fmt.Fprintf(&buf, "| p80 | %.2fs |\n", p80)
	fmt.Fprintf(&buf, "| p95 | %.2fs |\n", p95)
	fmt.Fprintf(&buf, "| Max | %.2fs |\n\n", sorted[len(sorted)-1])
	fmt.Fprintf(&buf, "<details>\n<summary>Individual Runs</summary>\n\n")
	fmt.Fprintf(&buf, "| Run | Duration | vs Direct |\n")
	fmt.Fprintf(&buf, "|----:|----------|-----------|\n")
	for i, v := range warmSec {
		fmt.Fprintf(&buf, "| %d | %.2fs | %s |\n", i+1, v, overheadPct(v, directSec))
	}
	fmt.Fprintf(&buf, "\n</details>\n")

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
