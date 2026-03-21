#!/usr/bin/env bash
#
# benchmark.sh — Clone a large repository via direct, cold cache, and warm cache
# paths and record timing data for analysis.
#
set -euo pipefail

REPO="${REPO:-django/django}"
GHP_HOST="${GHP_HOST:-127.0.0.1}"
GHP_PORT="${GHP_PORT:-8080}"
WARM_RUNS="${WARM_RUNS:-10}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_DIR="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="${RESULTS_DIR:-$BENCH_DIR/results}"
WORK_DIR=$(mktemp -d)

mkdir -p "$RESULTS_DIR/logs"

cleanup() {
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Portable high-resolution timestamp (works on macOS and Linux).
now() {
    python3 -c "import time; print(f'{time.time():.6f}')"
}

# Compute elapsed seconds from two timestamps.
elapsed() {
    python3 -c "print(f'{$2 - $1:.3f}')"
}

# Wait for GHP to accept connections.
wait_for_ghp() {
    echo "Waiting for GHP at ${GHP_HOST}:${GHP_PORT}..."
    for i in $(seq 1 60); do
        if curl -sf "http://${GHP_HOST}:${GHP_PORT}/auth/status" > /dev/null 2>&1; then
            echo "GHP is ready"
            return 0
        fi
        if [ "$i" -eq 60 ]; then
            echo "ERROR: GHP did not become ready within 60 seconds"
            return 1
        fi
        echo "  attempt $i/60..."
        sleep 1
    done
}

# Clone a repository, capture timing and verbose output.
#
# Usage: measure_clone <label> [git-clone-args...] <url>
#
# Prints the elapsed seconds to stdout. Stderr from git (including
# GIT_CURL_VERBOSE output) is saved to $RESULTS_DIR/logs/<label>-stderr.log.
measure_clone() {
    local label="$1"
    shift
    local target_dir="$WORK_DIR/$label"

    local start end duration
    start=$(now)
    git clone "$@" "$target_dir" 2>"$RESULTS_DIR/logs/${label}-stderr.log"
    end=$(now)
    duration=$(elapsed "$start" "$end")

    # Free disk space for subsequent clones.
    rm -rf "$target_dir"

    echo "$duration"
}

echo "============================================"
echo "  Git Clone Cache Performance Benchmark"
echo "============================================"
echo ""
echo "  Repository : ${REPO}"
echo "  GHP        : ${GHP_HOST}:${GHP_PORT}"
echo "  Warm runs  : ${WARM_RUNS}"
echo "  Work dir   : ${WORK_DIR}"
echo "  Results    : ${RESULTS_DIR}"
echo ""

wait_for_ghp
echo ""

# ── 1. Direct clone (baseline) ────────────────────────────────────────────────
echo "--- Direct clone ---"
direct_time=$(measure_clone "direct" "https://github.com/${REPO}.git")
echo "  Duration: ${direct_time}s"
echo ""

# Enable verbose curl output for all proxy clones so that the HTTP
# conversation is captured in the per-clone stderr log files.
export GIT_CURL_VERBOSE=1

# ── 2. Cold cache clone (first request through GHP) ──────────────────────────
echo "--- GHP cold cache clone ---"
cold_time=$(
    measure_clone "cold-cache" \
        -c "http.extraHeader=Host: github.com" \
        "http://${GHP_HOST}:${GHP_PORT}/${REPO}.git"
)
echo "  Duration: ${cold_time}s"
echo ""

# ── 3. Warm cache clones (subsequent requests through GHP) ───────────────────
echo "--- GHP warm cache clones (${WARM_RUNS} runs) ---"
warm_times=()
for i in $(seq 1 "$WARM_RUNS"); do
    t=$(
        measure_clone "warm-cache-$(printf '%02d' "$i")" \
            -c "http.extraHeader=Host: github.com" \
            "http://${GHP_HOST}:${GHP_PORT}/${REPO}.git"
    )
    warm_times+=("$t")
    echo "  Run $(printf '%2d' "$i"): ${t}s"
done
echo ""

# ── Write results JSON ────────────────────────────────────────────────────────
warm_json=$(printf '%s\n' "${warm_times[@]}" | python3 -c "
import sys, json
times = [float(line.strip()) for line in sys.stdin if line.strip()]
print(json.dumps(times))
")

cat > "$RESULTS_DIR/results.json" << ENDJSON
{
  "repo": "${REPO}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "ghp_host": "${GHP_HOST}",
  "ghp_port": "${GHP_PORT}",
  "direct": {
    "duration_seconds": ${direct_time}
  },
  "cold_cache": {
    "duration_seconds": ${cold_time}
  },
  "warm_cache": {
    "runs": ${warm_json}
  }
}
ENDJSON

echo "Results written to ${RESULTS_DIR}/results.json"
