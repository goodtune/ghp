// Command scoperig is the GHP scope regression rig: it mints scoped tokens
// on a live GHP instance, runs the scenario tree under rig/ and reports
// which documented scope claims hold.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/goodtune/ghp/tools/scoperig/fixtures"
	"github.com/goodtune/ghp/tools/scoperig/redact"
	"github.com/goodtune/ghp/tools/scoperig/report"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
	"github.com/goodtune/ghp/tools/scoperig/tokens"
)

// osExit is replaced in tests.
var osExit = os.Exit

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	deps := runDeps{OnManager: secondSignal(ctx, os.Stdout)}
	cmd := newRootCmd(os.Stdout, os.Stderr, os.Getenv, deps)
	err := cmd.ExecuteContext(ctx)
	stop()
	osExit(exitCode(err, os.Stderr))
}

// secondSignal returns an OnManager hook: once the first signal has
// cancelled ctx, a further SIGINT/SIGTERM revokes what it can, prints the
// remaining token ids and exits 2 (the next run's sweep finishes the job).
func secondSignal(ctx context.Context, out io.Writer) func(*tokens.Manager) {
	return func(m *tokens.Manager) {
		go func() {
			<-ctx.Done()
			m.RevokeOnSignal(func(left []string) {
				fmt.Fprintf(out, "interrupted again; leftover token ids: %s\n", strings.Join(left, " "))
				osExit(2)
			}, os.Interrupt, syscall.SIGTERM)
		}()
	}
}

func exitCode(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err != nil && ee.code != 0 {
			fmt.Fprintln(stderr, "scoperig:", redact.String(ee.err.Error()))
		}
		return ee.code
	}
	fmt.Fprintln(stderr, "scoperig:", redact.String(err.Error()))
	return 3 // preflight, cobra usage and config errors: could not start
}

type cliFlags struct {
	config, out, only             string
	skipKnown, keepGoing, verbose bool
	createFixtures                bool
}

func newRootCmd(stdout, stderr io.Writer, getenv func(string) string, deps runDeps) *cobra.Command {
	f := &cliFlags{}
	root := &cobra.Command{
		Use:           "scoperig",
		Short:         "GHP scope regression rig",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.PersistentFlags().StringVar(&f.config, "config", "rig/config.yaml", "rig config file")
	root.PersistentFlags().BoolVar(&f.verbose, "verbose", false, "print redacted exchanges")

	// load resolves flags over env over the config file.
	load := func() (*Config, error) {
		c, err := LoadConfig(getenv, f.config)
		if err != nil {
			return nil, &exitError{code: 3, err: err}
		}
		c.Out, c.Only = f.out, f.only
		c.SkipKnown, c.KeepGoing, c.Verbose = f.skipKnown, f.keepGoing, f.verbose
		c.CreateFixtures = f.createFixtures
		return c, nil
	}
	withOut := func(d runDeps) runDeps {
		if d.Out == nil {
			d.Out = stderr
		}
		return d
	}

	validate := &cobra.Command{
		Use:   "validate",
		Short: "Statically validate rig/ (no network, no environment needed)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := load()
			if err != nil {
				return err
			}
			_, errs := loadTree(c.Root)
			for _, e := range errs {
				fmt.Fprintln(stdout, redact.String(e.Error()))
			}
			fmt.Fprintf(stdout, "%d errors\n", len(errs))
			if len(errs) > 0 {
				return &exitError{code: 3, err: fmt.Errorf("validation failed with %d errors", len(errs))}
			}
			return nil
		},
	}

	run := &cobra.Command{
		Use:   "run",
		Short: "Run the scenarios against the instance",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := load()
			if err != nil {
				return err
			}
			rep, err := runRig(cmd.Context(), c, withOut(deps))
			if err != nil {
				return err
			}
			if err := rep.WriteTable(stdout); err != nil {
				return &exitError{code: 2, err: err}
			}
			if c.Out != "" {
				if err := writeJSON(c.Out, rep); err != nil {
					fmt.Fprintln(stderr, "scoperig:", err)
					return &exitError{code: 2, err: err}
				}
			}
			if code := report.ExitCode(rep); code != 0 {
				return &exitError{code: code, err: nil}
			}
			return nil
		},
	}
	run.Flags().BoolVar(&f.skipKnown, "skip-known", false, "skip scenarios with a known_issue")
	run.Flags().StringVar(&f.out, "out", "", "write the JSON report to FILE (for example /tmp/ghp-rig/reports/run.json)")
	run.Flags().StringVar(&f.only, "only", "", "run only scenario IDs matching GLOB (still sweeps and cleans up)")
	run.Flags().BoolVar(&f.keepGoing, "keep-going", true, "continue after a FAIL or ERROR")

	sweep := &cobra.Command{
		Use:   "sweep",
		Short: "Revoke tokens left by earlier rig runs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := load()
			if err != nil {
				return err
			}
			_, mgr, err := connect(cmd.Context(), c, deps)
			if err != nil {
				return err
			}
			defer mgr.RevokeAll(context.WithoutCancel(cmd.Context()))
			ids, err := mgr.Sweep(cmd.Context())
			fmt.Fprintf(stdout, "swept %d token(s): %s\n", len(ids), strings.Join(ids, " "))
			if err != nil {
				return &exitError{code: 2, err: err}
			}
			return nil
		},
	}

	fx := &cobra.Command{Use: "fixtures", Short: "Fixture repository management"}
	ensure := &cobra.Command{
		Use:   "ensure",
		Short: "Discover and seed fixture repositories A, B and W",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := load()
			if err != nil {
				return err
			}
			return ensureFixtures(cmd.Context(), c, deps, stdout)
		},
	}
	ensure.Flags().BoolVar(&f.createFixtures, "create-fixtures", false, "create missing fixture repositories (needs repo_create)")
	fx.AddCommand(ensure)

	root.AddCommand(validate, run, sweep, fx, newOracleCmd(stdout, stderr, getenv))
	return root
}

func writeJSON(name string, rep *report.Report) error {
	fh, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := rep.WriteJSON(fh); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
}

// connect runs preflight and builds a token manager for sweep and fixtures.
func connect(ctx context.Context, c *Config, deps runDeps) (*http.Client, *tokens.Manager, error) {
	deps.defaults()
	if err := c.RequireServer(); err != nil {
		return nil, nil, &exitError{code: 3, err: fmt.Errorf("%w: %v", ErrPreflight, err)}
	}
	hc := deps.HTTP
	if hc == nil {
		var err error
		if hc, err = c.HTTPClient(); err != nil {
			return nil, nil, &exitError{code: 3, err: err}
		}
	}
	if _, err := Preflight(ctx, c, hc); err != nil {
		return nil, nil, &exitError{code: 3, err: err}
	}
	pace := deps.Pace(max(c.TokenCreateRate, 1))
	mgr := tokens.NewManager(c.ServerURL, c.UserToken, deps.RunID(), hc, pace)
	if deps.OnManager != nil {
		deps.OnManager(mgr)
	}
	return hc, mgr, nil
}

func ensureFixtures(ctx context.Context, c *Config, deps runDeps, stdout io.Writer) (err error) {
	tree, errs := loadTree(c.Root)
	if len(errs) > 0 {
		return &exitError{code: 3, err: fmt.Errorf("validation failed: %w", errors.Join(errs...))}
	}
	hc, mgr, err := connect(ctx, c, deps)
	if err != nil {
		return err
	}
	defer func() {
		if left := mgr.RevokeAll(context.WithoutCancel(ctx)); len(left) > 0 {
			fmt.Fprintf(stdout, "leftover token ids: %s\n", strings.Join(left, " "))
			if err == nil {
				err = &exitError{code: 2, err: errors.New("token revocation failed")}
			}
		}
	}()
	vars := &scenario.Vars{RunID: strings.TrimPrefix(mgr.SessionID(), tokens.SessionPrefix), Host: c.Instance.Host,
		RepoA: repoRef(c.RepoA), RepoB: repoRef(c.RepoB), RepoW: repoRef(c.RepoW)}
	open, err := mgr.Create(ctx, tree.Profiles["open"], vars)
	if err != nil {
		return &exitError{code: 2, err: err}
	}
	caps, err := ProbeCapabilities(ctx, c, hc, open, vars)
	if err != nil {
		return &exitError{code: 3, err: err}
	}
	api := &handleAPI{hc: hc, base: "https://" + c.Instance.Host + "/api/v3", tok: open}
	var failed bool
	for _, repo := range []string{c.RepoA, c.RepoB, c.RepoW} {
		plan, err := fixtures.Ensure(ctx, api, repo, vars.Login, c.CreateFixtures, caps["repo_create"])
		if plan.Create {
			fmt.Fprintf(stdout, "%s: create repository\n", repo)
		}
		for _, s := range plan.Seed {
			fmt.Fprintf(stdout, "%s: %s\n", repo, s)
		}
		if err != nil {
			fmt.Fprintf(stdout, "%s: %s\n", repo, redact.String(err.Error()))
			failed = true
			continue
		}
		ref, fv, err := fixtures.Discover(ctx, api, repo)
		if err != nil {
			fmt.Fprintf(stdout, "%s: %s\n", repo, redact.String(err.Error()))
			failed = true
			continue
		}
		fmt.Fprintf(stdout, "%s: id=%d issue=#%d pr=#%d release=%d branch=%s label=%s\n",
			ref, ref.ID, fv.IssueNumber, fv.PRNumber, fv.ReleaseID, fv.Branch, fv.Label)
	}
	if failed {
		return &exitError{code: 3, err: errors.New("fixtures not ready")}
	}
	return nil
}
