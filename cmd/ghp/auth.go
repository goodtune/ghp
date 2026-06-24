package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// cliHTTPClient is used for short-lived CLI requests to the ghp server. A
// timeout is essential because `ghp auth` commands are often run in headless
// or SSH contexts where an unreachable server would otherwise hang indefinitely.
var cliHTTPClient = &http.Client{Timeout: 30 * time.Second}

type cliConfig struct {
	ServerURL string `yaml:"server_url"`
	UserToken string `yaml:"user_token"`

	// Dotvault, when set, sources CLI config fields (notably the session
	// token) from HashiCorp Vault via the dotvault client instead of from
	// this file. See dotvaultConfig and applyDotvault.
	Dotvault *dotvaultConfig `yaml:"dotvault,omitempty"`
}

// systemConfigPathOverride, when non-empty, replaces the computed system
// config path. Tests set it; production leaves it empty.
var systemConfigPathOverride string

// systemCLIConfigPath returns the OS-appropriate fleet-wide config file path.
// It mirrors dotvault's SystemConfigPath convention so an operator deploying
// both tools uses the same base layout: on Linux /etc/xdg/ghp/config.yaml
// (honouring XDG_CONFIG_DIRS), %ProgramData%\ghp\config.yaml on Windows, and
// /Library/Application Support/ghp/config.yaml on macOS. It is merged with the
// lowest precedence so an operator can deploy shared settings (server_url, a
// dotvault stanza) fleet-wide and have every user inherit them with zero
// per-user config.
func systemCLIConfigPath() string {
	if systemConfigPathOverride != "" {
		return systemConfigPathOverride
	}
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/ghp/config.yaml"
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "ghp", "config.yaml")
	default: // linux and others
		// Honour XDG_CONFIG_DIRS: use the first entry that actually has a
		// ghp config, falling back to the conventional /etc/xdg location.
		if dirs := os.Getenv("XDG_CONFIG_DIRS"); dirs != "" {
			for _, dir := range strings.Split(dirs, ":") {
				if dir == "" {
					continue
				}
				p := filepath.Join(dir, "ghp", "config.yaml")
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
		return "/etc/xdg/ghp/config.yaml"
	}
}

// userCLIConfigPath returns the per-user config file path, or "" when the home
// directory cannot be resolved.
func userCLIConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "ghp", "config.yaml")
}

// loadCLIConfigFileAt reads a single config file. A missing file (or empty
// path) yields an empty config and no error; a present but unreadable or
// malformed file returns an error so callers (notably set-token) can fail
// loudly rather than silently overwriting existing fields.
//
// When checkPerms is true — the user file, which may hold a session token — a
// warning is printed for permissions looser than 0600. The system file is
// expected to be world-readable across a fleet and to carry no secrets (the
// token is sourced per-user via dotvault), so that check is skipped for it.
func loadCLIConfigFileAt(path string, checkPerms bool) (*cliConfig, error) {
	cfg := &cliConfig{}
	if path == "" {
		return cfg, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("stating %s: %w", path, err)
	}
	if checkPerms {
		// 0177 masks owner-execute, group, and other permission bits.
		const insecurePermsMask = 0177
		if info.Mode().Perm()&insecurePermsMask != 0 {
			fmt.Fprintf(os.Stderr, "warning: config file %s has insecure permissions %04o (expected 0600)\n", path, info.Mode().Perm())
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return cfg, nil
}

// loadCLIConfigFile reads the per-user config file only. Save paths (auth
// login, set-token) use it so a transient environment, or the system file, is
// never written back into the user's config.
func loadCLIConfigFile() (*cliConfig, error) {
	return loadCLIConfigFileAt(userCLIConfigPath(), true)
}

// mergeCLIConfig overlays over onto base: any field set in over wins, otherwise
// base's value is kept. This lets the per-user config overload the fleet-wide
// system config field-by-field.
func mergeCLIConfig(base, over *cliConfig) *cliConfig {
	merged := *base
	if over.ServerURL != "" {
		merged.ServerURL = over.ServerURL
	}
	if over.UserToken != "" {
		merged.UserToken = over.UserToken
	}
	if over.Dotvault != nil {
		merged.Dotvault = over.Dotvault
	}
	return &merged
}

// loadCLIConfig builds the effective CLI config by merging, from lowest to
// highest precedence: the system file (/etc/ghp/config.yaml), the per-user
// file (~/.config/ghp/config.yaml), and the GHP_SERVER_URL / GHP_USER_TOKEN
// environment variables. dotvault-sourced fields override all of these and are
// resolved separately by loadCLIConfigAuthed.
func loadCLIConfig() (*cliConfig, error) {
	// Swallow file-level errors at both layers: a malformed file shouldn't
	// stop commands like `auth login` that can still work from env vars
	// alone. set-token uses loadCLIConfigFile directly and fails fast.
	sysCfg, err := loadCLIConfigFileAt(systemCLIConfigPath(), false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		sysCfg = &cliConfig{}
	}
	userCfg, err := loadCLIConfigFile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		userCfg = &cliConfig{}
	}
	cfg := mergeCLIConfig(sysCfg, userCfg)

	// Environment variable overrides (highest precedence among static sources).
	if v := os.Getenv("GHP_SERVER_URL"); v != "" {
		cfg.ServerURL = v
	}
	if v := os.Getenv("GHP_USER_TOKEN"); v != "" {
		cfg.UserToken = v
	}

	return cfg, nil
}

func saveCLIConfig(cfg *cliConfig) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	configDir := filepath.Join(home, ".config", "ghp")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(configDir, "config.yaml"), data, 0600)
}

// openBrowser attempts to open url in the system browser. Errors are silently
// ignored because callers always print a fallback URL for copy-paste.
//
// Openers like xdg-open commonly print diagnostics (e.g. "no DISPLAY") to
// stderr, which would leak into CLI output; redirect them to io.Discard.
func openBrowser(rawURL string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL)
	case "windows":
		// Avoid `cmd /c start` so URLs containing `&` (common in OAuth URLs)
		// are not interpreted by the Windows command shell.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default:
		cmd = exec.Command("xdg-open", rawURL)
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err == nil && cmd.Process != nil {
		_ = cmd.Process.Release()
	}
}

// deviceStartResponse is the JSON returned by POST /cli/auth/device.
type deviceStartResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// runDeviceLogin runs the OAuth device-authorization flow against the ghp
// server and returns the issued session token. The returned token is a
// long-lived `ghpr_` user session token suitable for persistence.
func runDeviceLogin(ctx context.Context, out io.Writer, serverURL string) (string, error) {
	startEndpoint, err := url.JoinPath(serverURL, "/cli/auth/device")
	if err != nil {
		return "", fmt.Errorf("building device-auth URL: %w", err)
	}
	startReq, err := http.NewRequestWithContext(ctx, "POST", startEndpoint, strings.NewReader(""))
	if err != nil {
		return "", err
	}
	startReq.Header.Set("Accept", "application/json")
	startResp, err := cliHTTPClient.Do(startReq)
	if err != nil {
		return "", fmt.Errorf("connecting to server: %w", err)
	}
	defer startResp.Body.Close()

	if startResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(startResp.Body, 4096))
		return "", fmt.Errorf("device-auth request failed (%d): %s", startResp.StatusCode, strings.TrimSpace(string(body)))
	}

	var ds deviceStartResponse
	if err := json.NewDecoder(io.LimitReader(startResp.Body, 64*1024)).Decode(&ds); err != nil {
		return "", fmt.Errorf("decoding device-auth response: %w", err)
	}
	if ds.DeviceCode == "" || ds.UserCode == "" || ds.VerificationURI == "" {
		return "", fmt.Errorf("device-auth response missing required fields")
	}

	// The CLI may receive an interval of 0 from a misconfigured server; clamp
	// to a sane minimum to avoid hammering the endpoint in a tight loop.
	pollInterval := time.Duration(ds.Interval) * time.Second
	if pollInterval < time.Second {
		pollInterval = 5 * time.Second
	}
	expiresAt := time.Now().Add(time.Duration(ds.ExpiresIn) * time.Second)
	if ds.ExpiresIn <= 0 {
		expiresAt = time.Now().Add(10 * time.Minute)
	}

	openURL := ds.VerificationURIComplete
	if openURL == "" {
		openURL = ds.VerificationURI
	}

	fmt.Fprintf(out, "Open this URL in a browser to authorize the CLI:\n  %s\n\n", openURL)
	fmt.Fprintf(out, "Confirm this code matches what the page displays:\n  %s\n\n", ds.UserCode)
	fmt.Fprintf(out, "Waiting for approval (Ctrl-C to cancel)...\n")

	if os.Getenv("GHP_NO_BROWSER") == "" {
		openBrowser(openURL)
	}

	tokenEndpoint, err := url.JoinPath(serverURL, "/cli/auth/device/token")
	if err != nil {
		return "", fmt.Errorf("building token URL: %w", err)
	}

	for {
		if time.Now().After(expiresAt) {
			return "", fmt.Errorf("authorization request expired before approval; run 'ghp auth login' again")
		}

		token, errCode, retryAfter, err := pollDeviceToken(ctx, tokenEndpoint, ds.DeviceCode)
		if err != nil {
			return "", err
		}
		if token != "" {
			return token, nil
		}

		// nextSleep is the delay before the following poll. Most paths use
		// the server-supplied poll interval; slow_down and HTTP 429 extend
		// it dynamically.
		nextSleep := pollInterval

		switch errCode {
		case "authorization_pending":
			// continue polling at interval
		case "slow_down":
			pollInterval += 5 * time.Second
			nextSleep = pollInterval
		case errCodeRateLimited:
			// Server (or upstream proxy) asked us to back off. Honour the
			// Retry-After header when present; otherwise fall back to
			// double the current poll interval, capped sensibly.
			wait := parseRetryAfter(retryAfter)
			if wait <= 0 {
				wait = pollInterval * 2
			}
			if wait > 60*time.Second {
				wait = 60 * time.Second
			}
			nextSleep = wait
		case "access_denied":
			return "", fmt.Errorf("authorization was denied")
		case "expired_token":
			return "", fmt.Errorf("authorization request expired before approval; run 'ghp auth login' again")
		case "invalid_request", "invalid_grant":
			return "", fmt.Errorf("server rejected device code: %s", errCode)
		case "server_error":
			// The server logged the underlying cause; the CLI cannot
			// recover, so surface a clear instruction instead of silently
			// retrying. Re-running 'ghp auth login' picks the issue up
			// after the operator addresses it.
			return "", fmt.Errorf("ghp server returned server_error; check the server logs and re-run 'ghp auth login'")
		default:
			return "", fmt.Errorf("unexpected error from server: %s", errCode)
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(nextSleep):
		}
	}
}

// errCodeRateLimited is a synthetic error code used internally by the
// device-flow polling loop to mean "the server's IP rate limiter rejected
// us; honour Retry-After and try again." It is not an RFC-8628 error code
// and never escapes pollDeviceToken's caller.
const errCodeRateLimited = "rate_limited"

// pollDeviceToken issues one POST /cli/auth/device/token. On success it
// returns (token, "", "", nil). On a recognised RFC-8628 error it returns
// ("", errorCode, "", nil). On HTTP 429 from the per-IP rate limiter it
// returns ("", errCodeRateLimited, retryAfter, nil) where retryAfter is the
// raw Retry-After header value (may be empty if the server didn't set one).
// On a transport or unexpected response it returns an error.
func pollDeviceToken(ctx context.Context, endpoint, deviceCode string) (string, string, string, error) {
	bodyJSON, _ := json.Marshal(map[string]string{"device_code": deviceCode})
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(bodyJSON))
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := cliHTTPClient.Do(req)
	if err != nil {
		// Treat ctx cancellation as a hard error; otherwise transient
		// network errors are surfaced to the user.
		if errors.Is(err, context.Canceled) {
			return "", "", "", err
		}
		return "", "", "", fmt.Errorf("polling token endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode == http.StatusOK {
		var success struct {
			SessionToken string `json:"session_token"`
			Username     string `json:"username"`
		}
		if err := json.Unmarshal(body, &success); err != nil {
			return "", "", "", fmt.Errorf("decoding token response: %w", err)
		}
		if success.SessionToken == "" {
			return "", "", "", fmt.Errorf("server returned empty session_token")
		}
		return success.SessionToken, "", "", nil
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		// The server's per-IP limiter (or an upstream proxy) is asking us
		// to back off. Hand the Retry-After header up to the polling loop
		// so it can sleep for the right amount of time instead of treating
		// this as a fatal error.
		return "", errCodeRateLimited, resp.Header.Get("Retry-After"), nil
	}

	var errResp struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &errResp)
	if errResp.Error == "" {
		return "", "", "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return "", errResp.Error, "", nil
}

// parseRetryAfter interprets an HTTP Retry-After header value, which is
// either delta-seconds (e.g. "5") or an HTTP-date. Returns 0 when the
// header is empty or malformed; the caller should fall back to its own
// default in that case.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with the ghp server",
	}

	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate to the ghp server",
		Long: `Authenticate to the ghp server using the device-authorization flow.

The CLI initiates a sign-in request, prints a URL on the ghp server itself,
and polls until the user approves it in a browser. No GitHub OAuth round-trip
involves the CLI directly: GitHub remains the identity provider for the ghp
web UI, but the CLI never sees a github.com URL.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.ServerURL == "" {
				return fmt.Errorf("server URL not configured. Set GHP_SERVER_URL or add server_url to ~/.config/ghp/config.yaml")
			}

			out := cmd.OutOrStdout()
			token, err := runDeviceLogin(cmd.Context(), out, cfg.ServerURL)
			if err != nil {
				return err
			}

			// Defensive check before writing to disk: every legitimate ghp
			// session token starts with "ghpr_". Refuse anything else so a
			// misconfigured or malicious server cannot persist garbage in
			// the user's config (matches the validation in `auth set-token`).
			if !strings.HasPrefix(token, "ghpr_") {
				return fmt.Errorf("server returned an invalid session token (expected 'ghpr_' prefix)")
			}

			// Persist the issued token. Read the file directly so a transient
			// GHP_SERVER_URL doesn't get written back to disk.
			fileCfg, err := loadCLIConfigFile()
			if err != nil {
				return err
			}
			fileCfg.UserToken = token
			if err := saveCLIConfig(fileCfg); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}
			if home, err := os.UserHomeDir(); err == nil {
				fmt.Fprintf(out, "\nToken saved to %s\n", filepath.Join(home, ".config", "ghp", "config.yaml"))
			} else {
				fmt.Fprintln(out, "\nToken saved.")
			}
			fmt.Fprintf(out, "Run 'ghp auth status' to verify.\n")
			return nil
		},
	}

	setTokenCmd := &cobra.Command{
		Use:   "set-token <token>",
		Short: "Save a session token to the local config file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			token := args[0]
			if !strings.HasPrefix(token, "ghpr_") {
				return fmt.Errorf("invalid token: expected a token starting with 'ghpr_'")
			}
			// Read the file directly — not loadCLIConfig — so a temporary
			// GHP_SERVER_URL in the environment doesn't get written back to disk.
			// Fail fast on a malformed file so we don't silently overwrite it.
			cfg, err := loadCLIConfigFile()
			if err != nil {
				return err
			}
			cfg.UserToken = token
			if err := saveCLIConfig(cfg); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}
			out := cmd.OutOrStdout()
			if home, err := os.UserHomeDir(); err == nil {
				fmt.Fprintf(out, "Token saved to %s\n", filepath.Join(home, ".config", "ghp", "config.yaml"))
			} else {
				fmt.Fprintln(out, "Token saved.")
			}
			fmt.Fprintf(out, "Run 'ghp auth status' to verify.\n")
			return nil
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show current authentication status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfigAuthed(cmd.Context())
			if err != nil {
				return err
			}
			if cfg.ServerURL == "" {
				return fmt.Errorf("server URL not configured")
			}
			if cfg.UserToken == "" {
				fmt.Fprintln(cmd.OutOrStdout(), "Not authenticated. Run 'ghp auth login' to authenticate.")
				return nil
			}

			endpoint, err := url.JoinPath(cfg.ServerURL, "/auth/status")
			if err != nil {
				return fmt.Errorf("building status URL: %w", err)
			}
			req, err := http.NewRequest("GET", endpoint, nil)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+cfg.UserToken)

			resp, err := cliHTTPClient.Do(req)
			if err != nil {
				return fmt.Errorf("connecting to server: %w", err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			var result map[string]interface{}
			json.Unmarshal(body, &result)

			out := cmd.OutOrStdout()
			if auth, ok := result["authenticated"].(bool); ok && auth {
				fmt.Fprintf(out, "Authenticated as: %s\n", result["username"])
				fmt.Fprintf(out, "Role: %s\n", result["role"])
			} else {
				fmt.Fprintln(out, "Not authenticated or session expired. Run 'ghp auth login'.")
			}

			return nil
		},
	}

	cmd.AddCommand(loginCmd, setTokenCmd, statusCmd)
	return cmd
}
