package proxy

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// slowBody delivers its payload only after a delay, like a client whose
// request body arrives in a later TCP segment than the headers.
type slowBody struct {
	r     *strings.Reader
	delay time.Duration
	slept bool
}

func (b *slowBody) Read(p []byte) (int, error) {
	if !b.slept {
		time.Sleep(b.delay)
		b.slept = true
	}
	return b.r.Read(p)
}

func (b *slowBody) Close() error { return nil }

func decisionSample(t *testing.T, stage string) (uint64, float64) {
	t.Helper()
	m := &dto.Metric{}
	obs := metrics.ProxyDecisionDuration.WithLabelValues(stage, "proxy", metrics.VhostAPI)
	if err := obs.(prometheus.Metric).Write(m); err != nil {
		t.Fatal(err)
	}
	return m.GetHistogram().GetSampleCount(), m.GetHistogram().GetSampleSum()
}

// A slow GraphQL body upload used to fall outside every timed stage (#355).
// It must now show in request_body_read, pipeline_other must stay small, and
// the slow_decision log line must carry the breakdown without the token.
func TestServeHTTP_GraphQL_SlowBodyIsTimedAndLogged(t *testing.T) {
	h, ghpToken := newScopeOnlyHandler(t, map[string]string{"pull_requests": "read"})

	var buf bytes.Buffer
	metrics.ConfigureSlowDecisionLog(slog.New(slog.NewJSONHandler(&buf, nil)), 10*time.Millisecond)
	t.Cleanup(func() { metrics.ConfigureSlowDecisionLog(nil, 0) })

	stages := []string{metrics.StageRequestBodyRead, metrics.StageRequestBuild, metrics.StagePipelineOther, metrics.StageTotal}
	beforeN := map[string]uint64{}
	beforeS := map[string]float64{}
	for _, s := range stages {
		beforeN[s], beforeS[s] = decisionSample(t, s)
	}

	const delay = 30 * time.Millisecond
	body := `{"query":"{ repository(owner: \"goodtune\", name: \"ghp\") { pullRequests(first: 1) { nodes { number } } } }"}`
	req := httptest.NewRequest("POST", "http://api.github.com/graphql", nil)
	req.Body = &slowBody{r: strings.NewReader(body), delay: delay}
	req.ContentLength = int64(len(body))
	req = req.WithContext(metrics.WithVhost(req.Context(), metrics.VhostAPI))
	req.Header.Set("Authorization", "Bearer "+ghpToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	for _, s := range stages {
		n, _ := decisionSample(t, s)
		if n-beforeN[s] != 1 {
			t.Errorf("stage %s: sample count delta %d, want 1", s, n-beforeN[s])
		}
	}
	_, bodySum := decisionSample(t, metrics.StageRequestBodyRead)
	bodyRead := bodySum - beforeS[metrics.StageRequestBodyRead]
	_, otherSum := decisionSample(t, metrics.StagePipelineOther)
	other := otherSum - beforeS[metrics.StagePipelineOther]
	_, totalSum := decisionSample(t, metrics.StageTotal)
	total := totalSum - beforeS[metrics.StageTotal]
	// Relative bounds: the sleep is real, so absolute slack flakes under
	// -race on a loaded runner.
	if bodyRead < (delay - 5*time.Millisecond).Seconds() {
		t.Errorf("request_body_read = %gs, want >= %gs", bodyRead, (delay - 5*time.Millisecond).Seconds())
	}
	if other >= total/2 {
		t.Errorf("pipeline_other = %gs of total %gs; the body wait leaked out of request_body_read", other, total)
	}

	out := buf.String()
	if strings.Count(out, `"msg":"slow_decision"`) != 1 {
		t.Fatalf("want one slow_decision line, got: %s", out)
	}
	for _, want := range []string{`"token_type":"proxy"`, `"request_body_read_ms"`, `"token_resolution_ms"`, `"pipeline_other_ms"`, `"path":"/graphql"`} {
		if !strings.Contains(out, want) {
			t.Errorf("slow_decision missing %s: %s", want, out)
		}
	}
	if strings.Contains(out, ghpToken) || strings.Contains(out, "ghx_") {
		t.Errorf("slow_decision log leaked the token: %s", out)
	}
}
