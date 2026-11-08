// Package latency reads GHP's decision-pipeline histograms from Prometheus
// for the window of one rig run and turns them into the report's advisory
// "Latency" section.
//
// The rig is the load: production traffic is too thin for quantiles, so the
// run window's own requests are measured. Quantiles are computed here from
// the increase of each cumulative bucket over the window, with the same
// linear interpolation as PromQL's histogram_quantile, so the maths is
// testable without a Prometheus server.
package latency

import (
	"math"
	"sort"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/report"
)

// Bucket is one cumulative histogram bucket: Count observations <= UpperBound.
type Bucket struct {
	UpperBound float64 // math.Inf(1) for the +Inf bucket
	Count      float64
}

// Quantile returns the q-quantile (0 <= q <= 1) of the cumulative buckets,
// interpolating linearly within the bucket that holds the rank, as PromQL's
// histogram_quantile does: the first bucket's lower bound is 0, and a rank
// in the +Inf bucket returns the highest finite upper bound. Bucket counts
// from increase() can be slightly non-monotonic; each count is raised to at
// least the one before it. It returns NaN when there are no observations or
// no +Inf bucket.
func Quantile(q float64, buckets []Bucket) float64 {
	if len(buckets) == 0 || q < 0 || q > 1 || math.IsNaN(q) {
		return math.NaN()
	}
	bs := append([]Bucket(nil), buckets...)
	sort.Slice(bs, func(i, j int) bool { return bs[i].UpperBound < bs[j].UpperBound })
	if !math.IsInf(bs[len(bs)-1].UpperBound, 1) {
		return math.NaN()
	}
	for i := 1; i < len(bs); i++ {
		if bs[i].Count < bs[i-1].Count {
			bs[i].Count = bs[i-1].Count
		}
	}
	total := bs[len(bs)-1].Count
	if total <= 0 {
		return math.NaN()
	}
	if len(bs) == 1 {
		return math.NaN() // only +Inf: nothing to interpolate
	}
	rank := q * total
	i := sort.Search(len(bs), func(i int) bool { return bs[i].Count >= rank })
	if i == len(bs)-1 {
		return bs[len(bs)-2].UpperBound
	}
	lower, prev := 0.0, 0.0
	if i > 0 {
		lower, prev = bs[i-1].UpperBound, bs[i-1].Count
	} else if bs[0].UpperBound <= 0 {
		return bs[0].UpperBound
	}
	upper, count := bs[i].UpperBound, bs[i].Count
	if count == prev {
		return upper
	}
	return lower + (upper-lower)*(rank-prev)/(count-prev)
}

// MinSamples is the sample count below which a quantile is flagged as
// resting on too few observations.
const MinSamples = 100

// Advisory p99 budgets (issue #321, from the v0.23.0 baseline).
var budgets = map[string]time.Duration{
	"scope_enforcement":       time.Millisecond,
	"graphql_analysis":        2 * time.Millisecond,
	"token_extraction":        500 * time.Microsecond,
	"border_policy_check":     500 * time.Microsecond,
	"scope_parsing":           500 * time.Microsecond,
	"username_resolution":     500 * time.Microsecond,
	"forward_proxy_selection": 500 * time.Microsecond,
	"token_resolution":        10 * time.Millisecond,
	"github_token_resolution": 15 * time.Millisecond,
	"total":                   15 * time.Millisecond,
}

// Budget returns the advisory p99 budget for stage, or 0 for none
// (upstream_roundtrip, redirect_head_check, cache_lookup, the end-to-end
// request and any stage added later).
func Budget(stage string) time.Duration { return budgets[stage] }

// Flag names in report.StageLatency.Flags.
const (
	FlagOverBudget = report.FlagOverBudget
	FlagLowSamples = report.FlagLowSamples
)

// Stage builds one report row from a stage's buckets, sum and count.
func Stage(stage, tokenType string, buckets []Bucket, sum, count float64) report.StageLatency {
	n := int(math.Round(count))
	row := report.StageLatency{Stage: stage, TokenType: tokenType, Samples: n,
		BudgetP99: Budget(stage).Seconds(), Flags: []string{}}
	if n > 0 {
		row.Mean = sum / count
		row.P50 = zeroNaN(Quantile(0.50, buckets))
		row.P95 = zeroNaN(Quantile(0.95, buckets))
		row.P99 = zeroNaN(Quantile(0.99, buckets))
	}
	if row.BudgetP99 > 0 && row.P99 > row.BudgetP99 {
		row.Flags = append(row.Flags, FlagOverBudget)
	}
	if n < MinSamples {
		row.Flags = append(row.Flags, FlagLowSamples)
	}
	return row
}

func zeroNaN(f float64) float64 {
	if math.IsNaN(f) {
		return 0
	}
	return f
}
