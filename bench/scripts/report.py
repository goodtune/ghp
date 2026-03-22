#!/usr/bin/env python3
"""Generate a markdown performance report from benchmark results."""

import json
import math
import os
import sys


def percentile(data: list[float], p: float) -> float:
    """Calculate the p-th percentile using linear interpolation."""
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (p / 100)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_data[int(k)]
    return sorted_data[int(f)] * (c - k) + sorted_data[int(c)] * (k - f)


def overhead_pct(value: float, baseline: float) -> str:
    """Format the percentage overhead relative to a baseline."""
    if baseline <= 0:
        return "N/A"
    pct = ((value - baseline) / baseline) * 100
    return f"{pct:+.1f}%"


def main() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    bench_dir = os.path.dirname(script_dir)
    results_dir = os.environ.get("RESULTS_DIR", os.path.join(bench_dir, "results"))
    results_file = os.path.join(results_dir, "results.json")

    if not os.path.exists(results_file):
        print(f"Results file not found: {results_file}", file=sys.stderr)
        print("Benchmark may not have run — skipping report.", file=sys.stderr)
        sys.exit(0)

    with open(results_file) as f:
        data = json.load(f)

    repo = data["repo"]
    timestamp = data["timestamp"]
    direct = data["direct"]["duration_seconds"]
    cold = data["cold_cache"]["duration_seconds"]
    warm_runs = data["warm_cache"]["runs"]

    if not warm_runs:
        print("No warm cache runs recorded — nothing to report.", file=sys.stderr)
        sys.exit(1)

    p50 = percentile(warm_runs, 50)
    p80 = percentile(warm_runs, 80)
    p95 = percentile(warm_runs, 95)
    warm_min = min(warm_runs)
    warm_max = max(warm_runs)
    warm_mean = sum(warm_runs) / len(warm_runs)

    # Enrich results.json with computed statistics.
    data["warm_cache"].update({
        "count": len(warm_runs),
        "min": round(warm_min, 3),
        "max": round(warm_max, 3),
        "mean": round(warm_mean, 3),
        "p50": round(p50, 3),
        "p80": round(p80, 3),
        "p95": round(p95, 3),
    })
    with open(results_file, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

    # Build markdown report.
    report = f"""\
## Git Clone Cache Performance Results

**Repository:** `{repo}`
**Date:** {timestamp}

### Summary

| Scenario | Duration | vs Direct |
|----------|----------|-----------|
| Direct clone | {direct:.2f}s | -- |
| GHP -- cold cache | {cold:.2f}s | {overhead_pct(cold, direct)} |
| GHP -- warm cache (p50) | {p50:.2f}s | {overhead_pct(p50, direct)} |
| GHP -- warm cache (p80) | {p80:.2f}s | {overhead_pct(p80, direct)} |
| GHP -- warm cache (p95) | {p95:.2f}s | {overhead_pct(p95, direct)} |

### Warm Cache Distribution ({len(warm_runs)} runs)

| Stat | Value |
|------|-------|
| Min | {warm_min:.2f}s |
| Mean | {warm_mean:.2f}s |
| p50 | {p50:.2f}s |
| p80 | {p80:.2f}s |
| p95 | {p95:.2f}s |
| Max | {warm_max:.2f}s |

<details>
<summary>Individual Runs</summary>

| Run | Duration | vs Direct |
|----:|----------|-----------|
"""
    for i, t in enumerate(warm_runs, 1):
        report += f"| {i} | {t:.2f}s | {overhead_pct(t, direct)} |\n"

    report += """
</details>
"""

    # Write report file.
    report_file = os.path.join(results_dir, "report.md")
    with open(report_file, "w") as f:
        f.write(report)

    # Print to stdout.
    print(report)

    # Append to GitHub Actions job summary if running in CI.
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as f:
            f.write(report)


if __name__ == "__main__":
    main()
