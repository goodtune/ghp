package latency

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeProm answers instant queries from a table keyed by a substring of the
// query, recording each query and its time parameter.
func fakeProm(t *testing.T, answers map[string]string) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/prefix/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer sekret" {
			t.Errorf("Authorization = %q", got)
		}
		q := r.URL.Query().Get("query")
		seen = append(seen, q+" @"+r.URL.Query().Get("time"))
		for k, v := range answers {
			if strings.Contains(q, k) {
				_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[` + v + `]}}`))
				return
			}
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	t.Cleanup(ts.Close)
	return ts, &seen
}

func vec(labels, value string) string {
	return `{"metric":{` + labels + `},"value":[1762502160,"` + value + `"]}`
}

func TestCollect(t *testing.T) {
	se := `"stage":"scope_enforcement","token_type":"proxy"`
	answers := map[string]string{
		"_bucket{job=\"ghp\"}[124s]))": strings.Join([]string{
			vec(se+`,"le":"0.00001"`, "10"), vec(se+`,"le":"0.000025"`, "50"),
			vec(se+`,"le":"0.00005"`, "90"), vec(se+`,"le":"0.0001"`, "100"),
			vec(se+`,"le":"+Inf"`, "100"),
		}, ","),
		"(stage, token_type) (increase(ghp_proxy_decision_duration_seconds_sum":   vec(se, "0.003"),
		"(stage, token_type) (increase(ghp_proxy_decision_duration_seconds_count": vec(se, "100"),
		"sum by (le) (increase(ghp_proxy_request_duration_seconds_bucket": strings.Join([]string{
			vec(`"le":"0.5"`, "40"), vec(`"le":"1"`, "50"), vec(`"le":"+Inf"`, "50"),
		}, ","),
		"sum(increase(ghp_proxy_request_duration_seconds_sum":   vec(``, "20"),
		"sum(increase(ghp_proxy_request_duration_seconds_count": vec(``, "50"),
		"ghp_build_info": vec(`"version":"0.25.0","revision":"d8f3b9de"`, "1"),
	}
	ts, seen := fakeProm(t, answers)
	c := &Client{BaseURL: ts.URL + "/prefix/", Bearer: "sekret", Selector: `job="ghp"`, HTTP: ts.Client()}
	start := time.Date(2026, 11, 7, 7, 49, 38, 0, time.UTC)
	end := start.Add(123500 * time.Millisecond)
	lat, err := c.Collect(context.Background(), start, end)
	if err != nil {
		t.Fatal(err)
	}
	if lat.Status != "ok" || lat.Version != "0.25.0" || lat.Revision != "d8f3b9de" || lat.WindowSeconds != 124 {
		t.Errorf("lat = %+v", lat)
	}
	if len(lat.Stages) != 2 || lat.Stages[0].Stage != "scope_enforcement" || lat.Stages[1].Stage != EndToEndStage {
		t.Fatalf("stages = %+v", lat.Stages)
	}
	if s := lat.Stages[0]; s.Samples != 100 || !near(s.P99, 0.000095) || !near(s.Mean, 0.00003) || len(s.Flags) != 0 {
		t.Errorf("scope_enforcement = %+v", s)
	}
	if s := lat.Stages[1]; s.Samples != 50 || s.TokenType != "all" || !near(s.Mean, 0.4) || s.BudgetP99 != 0 {
		t.Errorf("end_to_end = %+v", s)
	}
	for _, q := range *seen {
		if strings.HasPrefix(q, "group by") || strings.HasPrefix(q, "count(") {
			continue // the series-presence queries run at the start
		}
		if !strings.HasSuffix(q, " @"+strconv.FormatInt(end.Unix(), 10)) {
			t.Errorf("query not evaluated at end: %s", q)
		}
		if !strings.Contains(q, `{job="ghp"}`) {
			t.Errorf("query without selector: %s", q)
		}
	}
}

func TestCollect_Errors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"error","error":"parse error"}`))
	}))
	defer ts.Close()
	c := &Client{BaseURL: ts.URL, HTTP: ts.Client()}
	now := time.Now()
	if _, err := c.Collect(context.Background(), now.Add(-time.Minute), now); err == nil || !strings.Contains(err.Error(), "parse error") {
		t.Errorf("err = %v", err)
	}
	if _, err := c.Collect(context.Background(), now, now); err == nil {
		t.Error("empty window: want error")
	}
}

// TestCollect_FirstAppearance covers #360: a series that first appears in
// the window (agent tokens after a deploy) has increase() == 0, so its raw
// cumulative values at the end are used instead.
func TestCollect_FirstAppearance(t *testing.T) {
	start := time.Date(2026, 11, 8, 4, 18, 0, 0, time.UTC)
	end := start.Add(10 * time.Minute)
	at := func(tm time.Time) string { return strconv.FormatInt(tm.Unix(), 10) }
	px := `"stage":"scope_enforcement","token_type":"proxy"`
	ag := `"stage":"scope_enforcement","token_type":"agent"`
	type ans struct{ q, t, v string }
	answers := []ans{
		// Present at the start: proxy only.
		{"group by (stage, token_type) (ghp_proxy_decision_duration_seconds_count", at(start), vec(px, "1")},
		{"count(ghp_proxy_request_duration_seconds_count", at(start), ""},
		// increase(): proxy counted, agent missing its first sample.
		{"(stage, token_type, le) (increase(", at(end), strings.Join([]string{
			vec(px+`,"le":"0.0001"`, "40"), vec(px+`,"le":"+Inf"`, "40"),
			vec(ag+`,"le":"0.0001"`, "0"), vec(ag+`,"le":"+Inf"`, "0")}, ",")},
		{"(stage, token_type) (increase(ghp_proxy_decision_duration_seconds_sum", at(end), vec(px, "0.002") + "," + vec(ag, "0")},
		{"(stage, token_type) (increase(ghp_proxy_decision_duration_seconds_count", at(end), vec(px, "40") + "," + vec(ag, "0")},
		// Raw cumulative values at the end.
		{"(stage, token_type, le) (ghp_proxy_decision_duration_seconds_bucket", at(end), strings.Join([]string{
			vec(px+`,"le":"0.0001"`, "5000"), vec(px+`,"le":"+Inf"`, "5000"),
			vec(ag+`,"le":"0.0001"`, "9"), vec(ag+`,"le":"+Inf"`, "9")}, ",")},
		{"(stage, token_type) (ghp_proxy_decision_duration_seconds_sum", at(end), vec(px, "0.3") + "," + vec(ag, "0.00045")},
		{"(stage, token_type) (ghp_proxy_decision_duration_seconds_count", at(end), vec(px, "5000") + "," + vec(ag, "9")},
		// End-to-end: absent at the start, so raw values are used.
		{"sum by (le) (increase(ghp_proxy_request_duration_seconds_bucket", at(end), vec(`"le":"1"`, "2") + "," + vec(`"le":"+Inf"`, "2")},
		{"sum(increase(ghp_proxy_request_duration_seconds_sum", at(end), vec(``, "0.5")},
		{"sum(increase(ghp_proxy_request_duration_seconds_count", at(end), vec(``, "2")},
		{"sum by (le) (ghp_proxy_request_duration_seconds_bucket", at(end), vec(`"le":"1"`, "3") + "," + vec(`"le":"+Inf"`, "3")},
		{"sum(ghp_proxy_request_duration_seconds_sum", at(end), vec(``, "0.9")},
		{"sum(ghp_proxy_request_duration_seconds_count", at(end), vec(``, "3")},
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, tm := r.URL.Query().Get("query"), r.URL.Query().Get("time")
		res := ""
		for _, a := range answers {
			if strings.Contains(q, a.q) && tm == a.t {
				res = a.v
				break
			}
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[` + res + `]}}`))
	}))
	defer ts.Close()
	c := &Client{BaseURL: ts.URL, HTTP: ts.Client()}
	lat, err := c.Collect(context.Background(), start, end)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, s := range lat.Stages {
		got[s.Stage+"/"+s.TokenType] = s.Samples
	}
	if got["scope_enforcement/proxy"] != 40 {
		t.Errorf("proxy (present at start) samples = %d, want the increase 40", got["scope_enforcement/proxy"])
	}
	if got["scope_enforcement/agent"] != 9 {
		t.Errorf("agent (new in window) samples = %d, want the raw count 9", got["scope_enforcement/agent"])
	}
	if got[EndToEndStage+"/all"] != 3 {
		t.Errorf("end_to_end (new in window) samples = %d, want 3", got[EndToEndStage+"/all"])
	}
}

// TestCollect_NetTotalRow checks the derived total_excl_body_read row (#360).
func TestCollect_NetTotalRow(t *testing.T) {
	tot := `"stage":"total","token_type":"proxy"`
	rbr := `"stage":"request_body_read","token_type":"proxy"`
	answers := map[string]string{
		"(stage, token_type, le) (increase(": strings.Join([]string{
			vec(tot+`,"le":"0.001"`, "90"), vec(tot+`,"le":"0.05"`, "100"), vec(tot+`,"le":"+Inf"`, "100"),
			vec(rbr+`,"le":"0.001"`, "0"), vec(rbr+`,"le":"0.05"`, "10"), vec(rbr+`,"le":"+Inf"`, "10")}, ","),
		"(stage, token_type) (increase(ghp_proxy_decision_duration_seconds_sum":   vec(tot, "0.49") + "," + vec(rbr, "0.38"),
		"(stage, token_type) (increase(ghp_proxy_decision_duration_seconds_count": vec(tot, "100") + "," + vec(rbr, "10"),
		"group by (stage, token_type)":                                            vec(tot, "1") + "," + vec(rbr, "1"),
		"count(ghp_proxy_request_duration_seconds_count":                          vec(``, "1"),
	}
	ts, _ := fakeProm(t, answers)
	c := &Client{BaseURL: ts.URL + "/prefix/", Bearer: "sekret", HTTP: ts.Client()}
	now := time.Now()
	lat, err := c.Collect(context.Background(), now.Add(-time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	var raw, net *struct{ p99, budget float64 }
	for _, s := range lat.Stages {
		switch s.Stage {
		case "total":
			raw = &struct{ p99, budget float64 }{s.P99, s.BudgetP99}
		case NetTotalStage:
			net = &struct{ p99, budget float64 }{s.P99, s.BudgetP99}
		}
	}
	if raw == nil || net == nil {
		t.Fatalf("stages = %+v, want raw total and %s rows", lat.Stages, NetTotalStage)
	}
	if raw.budget != 0 || net.budget != 0.015 || net.p99 >= raw.p99 {
		t.Errorf("raw = %+v, net = %+v", *raw, *net)
	}
}
