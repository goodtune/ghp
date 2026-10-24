package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/goodtune/ghp/internal/webhook"
)

func newWebhooksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "webhooks",
		Short: "Inspect and subscribe to GitHub webhook deliveries (admin)",
		Long: `Inspect the server's GitHub webhook ingress and subscribe to the deliveries
it has stored in its embedded NATS JetStream stream.

Requires an admin session (see "ghp auth login") and a server with
webhooks.enabled set.`,
	}
	cmd.AddCommand(newWebhooksStatusCmd(), newWebhooksTailCmd())
	return cmd
}

// webhooksStatus mirrors the fields of GET /api/webhooks/status the CLI
// prints. Unknown fields are ignored so the CLI tolerates server additions.
type webhooksStatus struct {
	Enabled      bool   `json:"enabled"`
	IngressPath  string `json:"ingress_path"`
	IngressURL   string `json:"ingress_url"`
	GlobalSecret bool   `json:"global_secret_configured"`
	Ngrok        struct {
		Enabled   bool   `json:"enabled"`
		Connected bool   `json:"connected"`
		URL       string `json:"url"`
	} `json:"ngrok"`
	NATS struct {
		Listen        string `json:"listen"`
		ClientURL     string `json:"client_url"`
		AuthRequired  bool   `json:"auth_required"`
		Clients       int    `json:"clients"`
		Stream        string `json:"stream"`
		SubjectPrefix string `json:"subject_prefix"`
	} `json:"nats"`
	Stream struct {
		Messages  uint64 `json:"messages"`
		Bytes     uint64 `json:"bytes"`
		FirstSeq  uint64 `json:"first_seq"`
		LastSeq   uint64 `json:"last_seq"`
		Consumers int    `json:"consumers"`
		MaxAge    string `json:"max_age"`
		MaxBytes  int64  `json:"max_bytes"`
	} `json:"stream"`
	Apps []struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		GitHubAppID      int64  `json:"github_app_id"`
		HasWebhookSecret bool   `json:"has_webhook_secret"`
	} `json:"apps"`
}

func newWebhooksStatusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the webhook ingress URL, tunnel state and stream statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfigAuthed(cmd.Context())
			if err != nil {
				return err
			}
			resp, err := cliGet(cmd.Context(), cfg, "/api/webhooks/status", nil)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				return cliAPIError(resp.StatusCode, body)
			}
			if asJSON {
				fmt.Fprintln(cmd.OutOrStdout(), strings.TrimSpace(string(body)))
				return nil
			}
			var st webhooksStatus
			if err := json.Unmarshal(body, &st); err != nil {
				return fmt.Errorf("decoding status: %w", err)
			}
			out := cmd.OutOrStdout()
			if !st.Enabled {
				fmt.Fprintln(out, "Webhooks: disabled (set webhooks.enabled on the server)")
				return nil
			}
			fmt.Fprintln(out, "Webhooks: enabled")
			if st.IngressURL != "" {
				fmt.Fprintf(out, "Ingress URL:   %s\n", st.IngressURL)
			} else {
				fmt.Fprintf(out, "Ingress path:  %s (set server.base_url or enable ngrok for a public URL)\n", st.IngressPath)
			}
			switch {
			case !st.Ngrok.Enabled:
				fmt.Fprintln(out, "ngrok:         disabled")
			case st.Ngrok.Connected:
				fmt.Fprintf(out, "ngrok:         connected (%s)\n", st.Ngrok.URL)
			default:
				fmt.Fprintln(out, "ngrok:         connecting")
			}
			if st.NATS.Listen != "" {
				auth := "no auth token"
				if st.NATS.AuthRequired {
					auth = "token required"
				}
				fmt.Fprintf(out, "NATS:          %s (%s, %d clients)\n", st.NATS.ClientURL, auth, st.NATS.Clients)
			} else {
				fmt.Fprintln(out, "NATS:          in-process only")
			}
			fmt.Fprintf(out, "Stream:        %s on %s.> — %d deliveries, %d bytes, seq %d..%d, %d consumers (max_age %s, max_bytes %d)\n",
				st.NATS.Stream, st.NATS.SubjectPrefix, st.Stream.Messages, st.Stream.Bytes, st.Stream.FirstSeq, st.Stream.LastSeq, st.Stream.Consumers, st.Stream.MaxAge, st.Stream.MaxBytes)
			withSecret := 0
			for _, a := range st.Apps {
				if a.HasWebhookSecret {
					withSecret++
				}
			}
			fmt.Fprintf(out, "Secrets:       %d of %d apps have a webhook secret", withSecret, len(st.Apps))
			if st.GlobalSecret {
				_, _ = fmt.Fprint(out, "; server-wide fallback configured")
			}
			fmt.Fprintln(out)
			for _, a := range st.Apps {
				mark := "no secret"
				if a.HasWebhookSecret {
					mark = "secret set"
				}
				fmt.Fprintf(out, "  - %s (GitHub App %d, record %s): %s\n", a.Name, a.GitHubAppID, a.ID, mark)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print the raw status JSON")
	return cmd
}

func newWebhooksTailCmd() *cobra.Command {
	var (
		filter  string
		from    string
		durable string
		asJSON  bool
		payload bool
		count   int
	)
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Stream webhook deliveries as they arrive",
		Long: `Subscribe to the server's webhook delivery stream over server-sent events
and print each delivery.

By default one summary line is printed per delivery. --json prints the full
delivery envelope (headers, metadata and payload) as one JSON object per line,
suitable for piping into jq. --payload prints only the GitHub payload.

--filter is a NATS subject filter under the server's subject prefix, e.g.
  github.webhooks.*.pull_request.>        every pull_request event
  github.webhooks.*.*.*.myorg.>           everything for repositories owned by myorg
  github.webhooks.<app-record-id>.>       everything for one app

--from selects where to start: "new" (default) for deliveries that arrive from
now on, "all" to replay everything retained, or a stream sequence number.

--durable NAME creates a named server-side consumer that remembers its
position: deliveries are acknowledged only after they have been printed, so a
restarted tail with the same name resumes where the previous one stopped.

The connection is retried automatically on network errors, resuming after the
last delivery seen.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfigAuthed(cmd.Context())
			if err != nil {
				return err
			}
			if asJSON && payload {
				return errors.New("--json and --payload are mutually exclusive")
			}
			switch from {
			case "", "new", "all":
			default:
				if _, perr := strconv.ParseUint(from, 10, 64); perr != nil {
					return fmt.Errorf("--from must be \"new\", \"all\", or a sequence number (got %q)", from)
				}
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return tailWebhooks(ctx, cfg, tailOptions{
				filter: filter, from: from, durable: durable, asJSON: asJSON, payloadOnly: payload, count: count,
			}, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&filter, "filter", "", "NATS subject filter under the server's subject prefix (default: all deliveries)")
	cmd.Flags().StringVar(&from, "from", "new", `Start position: "new", "all", or a stream sequence number`)
	cmd.Flags().StringVar(&durable, "durable", "", "Durable consumer name; resumes from the last acknowledged delivery")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print one JSON envelope per delivery")
	cmd.Flags().BoolVar(&payload, "payload", false, "Print only the GitHub payload JSON per delivery")
	cmd.Flags().IntVar(&count, "count", 0, "Exit after this many deliveries (0 = run until interrupted)")
	return cmd
}

type tailOptions struct {
	filter, from, durable string
	asJSON, payloadOnly   bool
	count                 int
}

// tailWebhooks connects to the SSE stream and prints deliveries until ctx is
// cancelled or count deliveries have been printed. Transport errors trigger a
// reconnect that resumes after the last sequence seen via Last-Event-ID.
func tailWebhooks(ctx context.Context, cfg *cliConfig, opts tailOptions, out, errOut io.Writer) error {
	q := url.Values{}
	if opts.filter != "" {
		q.Set("filter", opts.filter)
	}
	if opts.from != "" {
		q.Set("from", opts.from)
	}
	if opts.durable != "" {
		q.Set("durable", opts.durable)
	}

	printed := 0
	var lastSeq uint64
	backoff := 2 * time.Second
	for {
		hdr := http.Header{}
		if lastSeq > 0 {
			hdr.Set("Last-Event-ID", strconv.FormatUint(lastSeq, 10))
		}
		resp, err := cliGet(ctx, cfg, "/api/webhooks/stream", q, hdr)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintf(errOut, "connection failed: %v; retrying in %s\n", err, backoff)
			if !sleepCtx(ctx, backoff) {
				return nil
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return cliAPIError(resp.StatusCode, body)
		}
		backoff = 2 * time.Second

		n, seq, done, rerr := readSSEStream(resp.Body, out, opts, printed, lastSeq)
		resp.Body.Close()
		printed, lastSeq = n, seq
		if done {
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		if rerr != nil {
			fmt.Fprintf(errOut, "stream ended: %v; reconnecting\n", rerr)
		} else {
			fmt.Fprintln(errOut, "stream ended; reconnecting")
		}
		if !sleepCtx(ctx, backoff) {
			return nil
		}
	}
}

// readSSEStream consumes one SSE connection. It returns the updated printed
// count and last sequence, whether the count limit was reached, and any read
// error.
func readSSEStream(body io.Reader, out io.Writer, opts tailOptions, printed int, lastSeq uint64) (int, uint64, bool, error) {
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	var (
		id   string
		data strings.Builder
		kind string
	)
	flush := func() bool {
		defer func() { id = ""; kind = ""; data.Reset() }()
		if data.Len() == 0 {
			return false
		}
		if kind == "error" {
			fmt.Fprintf(out, "server error: %s\n", data.String())
			return false
		}
		var env webhook.Envelope
		if err := json.Unmarshal([]byte(data.String()), &env); err != nil {
			return false
		}
		if env.Sequence > lastSeq {
			lastSeq = env.Sequence
		} else if id != "" {
			if v, err := strconv.ParseUint(id, 10, 64); err == nil && v > lastSeq {
				lastSeq = v
			}
		}
		printDelivery(out, &env, opts)
		printed++
		return opts.count > 0 && printed >= opts.count
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if flush() {
				return printed, lastSeq, true, nil
			}
		case strings.HasPrefix(line, ":"):
			// comment / heartbeat
		case strings.HasPrefix(line, "id:"):
			id = strings.TrimSpace(line[3:])
		case strings.HasPrefix(line, "event:"):
			kind = strings.TrimSpace(line[6:])
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if flush() {
		return printed, lastSeq, true, nil
	}
	return printed, lastSeq, false, sc.Err()
}

func printDelivery(out io.Writer, env *webhook.Envelope, opts tailOptions) {
	switch {
	case opts.payloadOnly:
		if len(env.Payload) > 0 {
			fmt.Fprintln(out, string(env.Payload))
		}
	case opts.asJSON:
		b, _ := json.Marshal(env)
		fmt.Fprintln(out, string(b))
	default:
		ev := env.Event
		if env.Action != "" {
			ev += "/" + env.Action
		}
		app := env.AppName
		if app == "" && env.AppRecordID != "" {
			app = env.AppRecordID
		}
		if app == "" {
			app = "-"
		}
		repo := env.Repository
		if repo == "" {
			repo = "-"
		}
		ts := env.ReceivedAt
		if ts.IsZero() {
			ts = env.StoredAt
		}
		fmt.Fprintf(out, "%s seq=%d %-28s %-40s app=%s sender=%s delivery=%s\n",
			ts.Local().Format(time.RFC3339), env.Sequence, ev, repo, app, orDash(env.Sender), env.Delivery)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// cliGet performs an authenticated GET against the ghp server.
func cliGet(ctx context.Context, cfg *cliConfig, path string, q url.Values, hdrs ...http.Header) (*http.Response, error) {
	u := cfg.ServerURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.UserToken)
	req.Header.Set("Accept", "application/json, text/event-stream")
	for _, h := range hdrs {
		for k, vs := range h {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to server: %w", err)
	}
	return resp, nil
}

func cliAPIError(status int, body []byte) error {
	var m struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &m)
	if m.Message != "" {
		return fmt.Errorf("server returned %d: %s", status, m.Message)
	}
	return fmt.Errorf("server returned %d: %s", status, strings.TrimSpace(string(body)))
}
