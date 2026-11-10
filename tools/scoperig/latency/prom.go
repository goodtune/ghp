package latency

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goodtune/ghp/tools/scoperig/report"
)

// EndToEndStage is the row name for ghp_proxy_request_duration_seconds.
const EndToEndStage = "end_to_end"

// Client queries a Prometheus HTTP API: a Prometheus base URL, or a Grafana
// datasource proxy URL such as <grafana>/api/datasources/proxy/uid/<uid>.
type Client struct {
	BaseURL string
	// Bearer, when set, is sent as "Authorization: Bearer <Bearer>".
	Bearer string
	// Selector is extra label matchers added to every series selector, for
	// example `job="ghp"`. Empty matches every series.
	Selector string
	HTTP     *http.Client
}

type sample struct {
	Metric map[string]string `json:"metric"`
	Value  [2]any            `json:"value"`
}

func (s sample) float() (float64, error) {
	str, ok := s.Value[1].(string)
	if !ok {
		return 0, fmt.Errorf("sample value is %T, want string", s.Value[1])
	}
	return strconv.ParseFloat(str, 64)
}

// query runs an instant query at t and returns the vector result.
func (c *Client) query(ctx context.Context, q string, t time.Time) ([]sample, error) {
	u := strings.TrimRight(c.BaseURL, "/") + "/api/v1/query?" + url.Values{
		"query": {q}, "time": {strconv.FormatInt(t.Unix(), 10)},
	}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if c.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.Bearer)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			ResultType string   `json:"resultType"`
			Result     []sample `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("prometheus query: HTTP %d: response is not JSON", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || doc.Status != "success" {
		return nil, fmt.Errorf("prometheus query: HTTP %d: %s", resp.StatusCode, doc.Error)
	}
	if doc.Data.ResultType != "vector" {
		return nil, fmt.Errorf("prometheus query: result type %q, want vector", doc.Data.ResultType)
	}
	return doc.Data.Result, nil
}

func (c *Client) sel(metric string) string {
	return metric + "{" + c.Selector + "}"
}

type key struct{ stage, tokenType string }

type series struct {
	buckets    []Bucket
	sum, count float64
}

// Collect queries the run window [start, end] (end is the evaluation time,
// after the scrape wait) and returns the report section. Errors are
// returned for the caller to record as LatencyUnavailable.
func (c *Client) Collect(ctx context.Context, start, end time.Time) (*report.Latency, error) {
	win := int(math.Ceil(end.Sub(start).Seconds()))
	if win < 1 {
		return nil, errors.New("run window is empty")
	}
	rng := "[" + strconv.Itoa(win) + "s]"
	stages := map[key]*series{}
	get := func(k key) *series {
		s, ok := stages[k]
		if !ok {
			s = &series{}
			stages[k] = s
		}
		return s
	}

	const dec = "ghp_proxy_decision_duration_seconds"
	const e2e = "ghp_proxy_request_duration_seconds"
	type spec struct {
		q     string
		apply func(sample, float64) error
	}
	keyOf := func(s sample) key { return key{s.Metric["stage"], s.Metric["token_type"]} }
	e2eKey := key{EndToEndStage, "all"}
	addBucket := func(k key, s sample, v float64) error {
		le, err := parseLe(s.Metric["le"])
		if err != nil {
			return err
		}
		get(k).buckets = append(get(k).buckets, Bucket{UpperBound: le, Count: v})
		return nil
	}
	specs := []spec{
		{"sum by (stage, token_type, le) (increase(" + c.sel(dec+"_bucket") + rng + "))",
			func(s sample, v float64) error { return addBucket(keyOf(s), s, v) }},
		{"sum by (stage, token_type) (increase(" + c.sel(dec+"_sum") + rng + "))",
			func(s sample, v float64) error { get(keyOf(s)).sum = v; return nil }},
		{"sum by (stage, token_type) (increase(" + c.sel(dec+"_count") + rng + "))",
			func(s sample, v float64) error { get(keyOf(s)).count = v; return nil }},
		{"sum by (le) (increase(" + c.sel(e2e+"_bucket") + rng + "))",
			func(s sample, v float64) error { return addBucket(e2eKey, s, v) }},
		{"sum(increase(" + c.sel(e2e+"_sum") + rng + "))",
			func(_ sample, v float64) error { get(e2eKey).sum = v; return nil }},
		{"sum(increase(" + c.sel(e2e+"_count") + rng + "))",
			func(_ sample, v float64) error { get(e2eKey).count = v; return nil }},
	}
	run := func(specs []spec, at time.Time) error {
		for _, sp := range specs {
			res, err := c.query(ctx, sp.q, at)
			if err != nil {
				return err
			}
			for _, s := range res {
				v, err := s.float()
				if err != nil {
					return err
				}
				if err := sp.apply(s, v); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := run(specs, end); err != nil {
		return nil, err
	}

	// #360: increase() never counts a series' first sample, so a series
	// that first appeared inside the window (agent tokens after a deploy)
	// shows 0. Find the series present at the start; for every other key,
	// use the raw cumulative values at the end, since a series that did
	// not exist at the start began at zero. A counter reset inside the
	// window for such a series is not detected.
	present := map[key]bool{}
	e2ePresent := false
	if err := run([]spec{
		{"group by (stage, token_type) (" + c.sel(dec+"_count") + ")",
			func(s sample, _ float64) error { present[keyOf(s)] = true; return nil }},
		{"count(" + c.sel(e2e+"_count") + ")",
			func(_ sample, v float64) error { e2ePresent = v > 0; return nil }},
	}, start); err != nil {
		return nil, err
	}
	fresh := map[key]*series{}
	getFresh := func(k key) *series {
		s, ok := fresh[k]
		if !ok {
			s = &series{}
			fresh[k] = s
		}
		return s
	}
	freshBucket := func(k key, s sample, v float64) error {
		le, err := parseLe(s.Metric["le"])
		if err != nil {
			return err
		}
		getFresh(k).buckets = append(getFresh(k).buckets, Bucket{UpperBound: le, Count: v})
		return nil
	}
	if err := run([]spec{
		{"sum by (stage, token_type, le) (" + c.sel(dec+"_bucket") + ")",
			func(s sample, v float64) error { return freshBucket(keyOf(s), s, v) }},
		{"sum by (stage, token_type) (" + c.sel(dec+"_sum") + ")",
			func(s sample, v float64) error { getFresh(keyOf(s)).sum = v; return nil }},
		{"sum by (stage, token_type) (" + c.sel(dec+"_count") + ")",
			func(s sample, v float64) error { getFresh(keyOf(s)).count = v; return nil }},
		{"sum by (le) (" + c.sel(e2e+"_bucket") + ")",
			func(s sample, v float64) error { return freshBucket(e2eKey, s, v) }},
		{"sum(" + c.sel(e2e+"_sum") + ")",
			func(_ sample, v float64) error { getFresh(e2eKey).sum = v; return nil }},
		{"sum(" + c.sel(e2e+"_count") + ")",
			func(_ sample, v float64) error { getFresh(e2eKey).count = v; return nil }},
	}, end); err != nil {
		return nil, err
	}
	for k, f := range fresh {
		if k == e2eKey {
			if e2ePresent {
				continue
			}
		} else if present[k] {
			continue
		}
		stages[k] = f
	}

	lat := &report.Latency{Status: report.LatencyOK, WindowSeconds: win, Stages: []report.StageLatency{}}
	bi, err := c.query(ctx, "max by (version, revision) ("+c.sel("ghp_build_info")+")", end)
	if err != nil {
		return nil, err
	}
	if len(bi) > 0 {
		// Several series mean a deploy inside the window: list them all.
		var vs, rs []string
		sort.Slice(bi, func(i, j int) bool { return bi[i].Metric["version"] < bi[j].Metric["version"] })
		for _, s := range bi {
			vs, rs = append(vs, s.Metric["version"]), append(rs, s.Metric["revision"])
		}
		lat.Version, lat.Revision = strings.Join(vs, ","), strings.Join(rs, ",")
	}

	keys := make([]key, 0, len(stages))
	for k := range stages {
		if k.stage == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		oi, oj := stageOrder(keys[i].stage), stageOrder(keys[j].stage)
		if oi != oj {
			return oi < oj
		}
		if keys[i].stage != keys[j].stage {
			return keys[i].stage < keys[j].stage
		}
		return keys[i].tokenType < keys[j].tokenType
	})
	for _, k := range keys {
		s := stages[k]
		lat.Stages = append(lat.Stages, Stage(k.stage, k.tokenType, s.buckets, s.sum, s.count))
		if k.stage == "total" {
			r := stages[key{"request_body_read", k.tokenType}]
			if r == nil {
				r = &series{}
			}
			lat.Stages = append(lat.Stages, NetTotal(k.tokenType, s.buckets, s.sum, s.count, r.buckets, r.sum, r.count))
		}
	}
	return lat, nil
}

// order lists stages in pipeline order for the report; unknown stages sort
// after them alphabetically, then the end-to-end row.
var order = []string{
	"token_extraction", "border_policy_check", "token_resolution", "username_resolution",
	"scope_parsing", "scope_enforcement", "graphql_analysis", "github_token_resolution",
	"enterprise_exception", "forward_proxy_selection", "cache_lookup", "request_body_read",
	"request_build", "pipeline_other", "total", NetTotalStage, "upstream_roundtrip", "redirect_head_check",
}

func stageOrder(s string) int {
	if s == EndToEndStage {
		return len(order) + 1
	}
	for i, o := range order {
		if o == s {
			return i
		}
	}
	return len(order)
}

func parseLe(s string) (float64, error) {
	if s == "+Inf" {
		return math.Inf(1), nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("bucket le %q: %w", s, err)
	}
	return f, nil
}
