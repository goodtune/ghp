package metrics

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// decisionTrace accumulates the stage durations of one request so that the
// untimed remainder of the total (pipeline_other) can be derived and a slow
// decision can be explained from a single log line (#355).
type decisionTrace struct {
	method string
	path   string

	mu     sync.Mutex
	done   bool
	order  []string
	stages map[string]time.Duration
}

type decisionTraceKey struct{}

// WithDecisionTrace returns a copy of ctx that carries a fresh per-request
// stage trace. Every ObserveDecision call with the returned context (or one
// derived from it) adds its duration to the trace until the total stage is
// observed. method and path appear only in the slow-decision log line.
func WithDecisionTrace(ctx context.Context, method, path string) context.Context {
	return context.WithValue(ctx, decisionTraceKey{}, &decisionTrace{
		method: method,
		path:   path,
		stages: make(map[string]time.Duration),
	})
}

func decisionTraceFrom(ctx context.Context) *decisionTrace {
	if ctx == nil {
		return nil
	}
	tr, _ := ctx.Value(decisionTraceKey{}).(*decisionTrace)
	return tr
}

func (t *decisionTrace) add(stage string, d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Stages after total (upstream_roundtrip, forward_proxy_selection) are
	// not part of the pre-forward overhead.
	if t.done {
		return
	}
	if _, ok := t.stages[stage]; !ok {
		t.order = append(t.order, stage)
	}
	t.stages[stage] += d
}

// finish marks the trace complete and returns a copy of the stages in the
// order first observed plus their sum. ok is false when finish already ran.
func (t *decisionTrace) finish() (order []string, stages map[string]time.Duration, sum time.Duration, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return nil, nil, 0, false
	}
	t.done = true
	stages = make(map[string]time.Duration, len(t.stages))
	for k, v := range t.stages {
		stages[k] = v
		sum += v
	}
	return append([]string(nil), t.order...), stages, sum, true
}

type slowDecisionConfig struct {
	logger    *slog.Logger
	threshold time.Duration
}

var slowDecision atomic.Pointer[slowDecisionConfig]

// ConfigureSlowDecisionLog sets the logger and threshold for the
// slow_decision warn line. A nil logger or a threshold <= 0 disables it.
func ConfigureSlowDecisionLog(logger *slog.Logger, threshold time.Duration) {
	if logger == nil || threshold <= 0 {
		slowDecision.Store(nil)
		return
	}
	slowDecision.Store(&slowDecisionConfig{logger: logger, threshold: threshold})
}

func ms(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

// finishDecision runs when the total stage is observed: it records
// pipeline_other for traced requests and logs decisions at or above the
// configured threshold. The token itself is never available here.
func finishDecision(ctx context.Context, tokenType, vhost string, total time.Duration) {
	var (
		order  []string
		stages map[string]time.Duration
		other  time.Duration
		traced bool
		tr     = decisionTraceFrom(ctx)
	)
	if tr != nil {
		var sum time.Duration
		order, stages, sum, traced = tr.finish()
		if traced {
			other = max(total-sum, 0)
			ProxyDecisionDuration.WithLabelValues(StagePipelineOther, tokenType, vhost).Observe(other.Seconds())
		}
	}

	cfg := slowDecision.Load()
	if cfg == nil || total < cfg.threshold {
		return
	}
	attrs := []any{
		"token_type", tokenType,
		"vhost", vhost,
		"total_ms", ms(total),
	}
	if traced {
		attrs = append(attrs, "method", tr.method, "path", tr.path, "pipeline_other_ms", ms(other))
		for _, s := range order {
			attrs = append(attrs, s+"_ms", ms(stages[s]))
		}
	}
	cfg.logger.Warn("slow_decision", attrs...)
}
