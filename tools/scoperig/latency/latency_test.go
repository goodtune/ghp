package latency

import (
	"math"
	"reflect"
	"testing"
)

var inf = math.Inf(1)

// fixture is a decision-histogram increase over a run window: 100
// observations across GHP's finest decision buckets.
var fixture = []Bucket{
	{0.00001, 10}, {0.000025, 50}, {0.00005, 90}, {0.0001, 100}, {0.00025, 100}, {inf, 100},
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-12 }

func TestQuantile(t *testing.T) {
	shuffled := []Bucket{fixture[3], fixture[5], fixture[0], fixture[2], fixture[1], fixture[4]}
	tests := []struct {
		name    string
		q       float64
		buckets []Bucket
		want    float64
	}{
		{"p05 in first bucket interpolates from 0", 0.05, fixture, 0.000005},
		{"p50 on a bucket boundary", 0.50, fixture, 0.000025},
		{"p95", 0.95, fixture, 0.000075},
		{"p99", 0.99, fixture, 0.000095},
		{"p100 is the last bucket holding observations", 1, fixture, 0.0001},
		{"unsorted input", 0.95, shuffled, 0.000075},
		{"rank in +Inf returns highest finite bound", 0.99, []Bucket{{0.001, 1}, {0.005, 2}, {inf, 10}}, 0.005},
		{"non-monotonic increase is clamped", 0.75, []Bucket{{0.001, 4}, {0.002, 3.9}, {0.004, 8}, {inf, 8}}, 0.003},
		{"no observations", 0.5, []Bucket{{0.001, 0}, {inf, 0}}, math.NaN()},
		{"no +Inf bucket", 0.5, []Bucket{{0.001, 3}}, math.NaN()},
		{"only +Inf", 0.5, []Bucket{{inf, 3}}, math.NaN()},
		{"empty", 0.5, nil, math.NaN()},
		{"q out of range", 1.5, fixture, math.NaN()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Quantile(tt.q, tt.buckets)
			if math.IsNaN(tt.want) {
				if !math.IsNaN(got) {
					t.Errorf("Quantile = %v, want NaN", got)
				}
				return
			}
			if !near(got, tt.want) {
				t.Errorf("Quantile = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStage(t *testing.T) {
	tests := []struct {
		name      string
		stage     string
		buckets   []Bucket
		sum, cnt  float64
		wantFlags []string
		wantP99   float64
		budget    float64
	}{
		{"within budget", "scope_enforcement", fixture, 0.003, 100, []string{}, 0.000095, 0.001},
		{"cheap stage over 500us", "scope_parsing", []Bucket{{0.0001, 0}, {0.001, 200}, {inf, 200}}, 0.1, 200, []string{FlagOverBudget}, 0.0001 + 0.0009*0.99, 0.0005},
		{"low samples", NetTotalStage, []Bucket{{0.005, 10}, {inf, 10}}, 0.02, 10, []string{FlagLowSamples}, 0.005 * 0.99, 0.015},
		{"raw total has no budget (#360)", "total", []Bucket{{0.05, 200}, {inf, 200}}, 2, 200, []string{}, 0.05 * 0.99, 0},
		{"no budget stage", "upstream_roundtrip", []Bucket{{1, 150}, {2.5, 150}, {inf, 150}}, 60, 150, []string{}, 0.99, 0},
		{"no samples", "graphql_analysis", []Bucket{{0.001, 0}, {inf, 0}}, 0, 0, []string{FlagLowSamples}, 0, 0.002},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := Stage(tt.stage, "proxy", tt.buckets, tt.sum, tt.cnt)
			if !reflect.DeepEqual(row.Flags, tt.wantFlags) {
				t.Errorf("flags = %v, want %v", row.Flags, tt.wantFlags)
			}
			if !near(row.P99, tt.wantP99) {
				t.Errorf("p99 = %v, want %v", row.P99, tt.wantP99)
			}
			if !near(row.BudgetP99, tt.budget) {
				t.Errorf("budget = %v, want %v", row.BudgetP99, tt.budget)
			}
			if tt.cnt > 0 && !near(row.Mean, tt.sum/tt.cnt) {
				t.Errorf("mean = %v", row.Mean)
			}
			if row.Samples != int(tt.cnt) {
				t.Errorf("samples = %d", row.Samples)
			}
		})
	}
}

func TestBudgets(t *testing.T) {
	want := map[string]float64{
		"scope_enforcement": 0.001, "graphql_analysis": 0.002, "token_extraction": 0.0005,
		"border_policy_check": 0.0005, "scope_parsing": 0.0005, "username_resolution": 0.0005,
		"forward_proxy_selection": 0.0005, "token_resolution": 0.010,
		"github_token_resolution": 0.015, "total": 0, NetTotalStage: 0.015,
		"upstream_roundtrip": 0, "cache_lookup": 0, EndToEndStage: 0,
	}
	for stage, b := range want {
		if got := Budget(stage).Seconds(); !near(got, b) {
			t.Errorf("Budget(%s) = %v, want %v", stage, got, b)
		}
	}
}

func TestNetTotal(t *testing.T) {
	// 100 requests: 90 REST totals of ~1ms, 10 GraphQL totals of ~40ms whose
	// body read took ~38ms. The p99 of total sits in the slow tail; minus
	// the (zero-padded) body-read p99 it is the ~2ms of GHP overhead.
	total := []Bucket{{0.001, 90}, {0.0025, 90}, {0.05, 100}, {inf, 100}}
	rbr := []Bucket{{0.001, 0}, {0.035, 0}, {0.04, 10}, {inf, 10}}
	row := NetTotal("proxy", total, 0.09+0.4, 100, rbr, 0.38, 10)
	if row.Stage != NetTotalStage || row.TokenType != "proxy" || row.Samples != 100 || !row.Estimate {
		t.Fatalf("row = %+v", row)
	}
	wantP99 := math.Max(0, Quantile(0.99, total)-Quantile(0.99, padZero(rbr, 100)))
	if !near(row.P99, wantP99) || row.P99 < 0 {
		t.Errorf("p99 = %v, want %v", row.P99, wantP99)
	}
	if !near(row.Mean, (0.49-0.38)/100) {
		t.Errorf("mean = %v", row.Mean)
	}
	if !near(row.BudgetP99, 0.015) {
		t.Errorf("budget = %v", row.BudgetP99)
	}
	for _, f := range row.Flags {
		if f == FlagOverBudget {
			t.Errorf("flags = %v: the body read must not count against the budget", row.Flags)
		}
	}
	// The raw total row for the same data is over the old 15ms budget.
	if raw := Quantile(0.99, total); raw <= 0.015 {
		t.Fatalf("fixture: raw total p99 %v should exceed 15ms", raw)
	}

	t.Run("no body reads equals total", func(t *testing.T) {
		row := NetTotal("agent", total, 0.49, 100, nil, 0, 0)
		if !near(row.P99, Quantile(0.99, total)) || !near(row.Mean, 0.0049) {
			t.Errorf("row = %+v", row)
		}
	})
	t.Run("clamped at zero", func(t *testing.T) {
		row := NetTotal("proxy", []Bucket{{0.001, 10}, {inf, 10}}, 0.005, 10,
			[]Bucket{{0.001, 0}, {0.1, 10}, {inf, 10}}, 0.5, 10)
		if row.P50 < 0 || row.P95 < 0 || row.P99 < 0 || row.Mean < 0 {
			t.Errorf("negative estimate: %+v", row)
		}
	})
	t.Run("no samples", func(t *testing.T) {
		row := NetTotal("proxy", nil, 0, 0, nil, 0, 0)
		if row.Samples != 0 || row.P99 != 0 {
			t.Errorf("row = %+v", row)
		}
	})
}
