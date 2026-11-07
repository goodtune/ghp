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
