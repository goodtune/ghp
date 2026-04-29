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
}

// loadCLIConfigFile reads the on-disk config file without applying any env
// var overrides. A missing file yields an empty config and no error; a present
// but unreadable or malformed file returns an error so callers (notably
// set-token) can fail loudly rather than silently overwriting existing fields.
func loadCLIConfigFile() (*cliConfig, error) {
	cfg := &cliConfig{}
	home, err := os.UserHomeDir()
	if err != nil {
		return cfg, nil
	}
	configPath := filepath.Join(home, ".config", "ghp", "config.yaml")
	info, err := os.Stat(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("stating %s: %w", configPath, err)
	}
	// 0177 masks owner-execute, group, and other permission bits.
	const insecurePermsMask = 0177
	if info.Mode().Perm()&insecurePermsMask != 0 {
		fmt.Fprintf(os.Stderr, "warning: config file %s has insecure permissions %04o (expected 0600)\n", configPath, info.Mode().Perm())
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", configPath, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", configPath, err)
	}
	return cfg, nil
}

func loadCLIConfig() (*cliConfig, error) {
	// For the env-aware loader, swallow file-level errors: a malformed file
	// shouldn't stop commands like `auth login` that can still work from env
	// vars alone. set-token uses loadCLIConfigFile directly and fails fast.
	cfg, err := loadCLIConfigFile()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		cfg = &cliConfig{}
	}

	// Environment variable overrides.
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

		token, errCode, err := pollDeviceToken(ctx, tokenEndpoint, ds.DeviceCode)
		if err != nil {
			return "", err
		}
		if token != "" {
			return token, nil
		}

		switch errCode {
		case "authorization_pending":
			// continue polling at interval
		case "slow_down":
			pollInterval += 5 * time.Second
		case "access_denied":
			return "", fmt.Errorf("authorization was denied")
		case "expired_token":
			return "", fmt.Errorf("authorization request expired before approval; run 'ghp auth login' again")
		case "invalid_request", "invalid_grant":
			return "", fmt.Errorf("server rejected device code: %s", errCode)
		default:
			return "", fmt.Errorf("unexpected error from server: %s", errCode)
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// pollDeviceToken issues one POST /cli/auth/device/token. On success it
// returns (token, "", nil). On a recognized RFC-8628 error it returns
// ("", errorCode, nil). On a transport or unexpected response it returns an error.
func pollDeviceToken(ctx context.Context, endpoint, deviceCode string) (string, string, error) {
	bodyJSON, _ := json.Marshal(map[string]string{"device_code": deviceCode})
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(bodyJSON))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := cliHTTPClient.Do(req)
	if err != nil {
		// Treat ctx cancellation as a hard error; otherwise transient
		// network errors are surfaced to the user.
		if errors.Is(err, context.Canceled) {
			return "", "", err
		}
		return "", "", fmt.Errorf("polling token endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode == http.StatusOK {
		var success struct {
			SessionToken string `json:"session_token"`
			Username     string `json:"username"`
		}
		if err := json.Unmarshal(body, &success); err != nil {
			return "", "", fmt.Errorf("decoding token response: %w", err)
		}
		if success.SessionToken == "" {
			return "", "", fmt.Errorf("server returned empty session_token")
		}
		return success.SessionToken, "", nil
	}

	var errResp struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &errResp)
	if errResp.Error == "" {
		return "", "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return "", errResp.Error, nil
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
			cfg, err := loadCLIConfig()
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
