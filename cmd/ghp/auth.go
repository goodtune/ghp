package main

import (
	"encoding/json"
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

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with the ghp server",
	}

	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate via GitHub OAuth",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.ServerURL == "" {
				return fmt.Errorf("server URL not configured. Set GHP_SERVER_URL or add server_url to ~/.config/ghp/config.yaml")
			}

			// Ask the server for the GitHub OAuth URL. The server generates a
			// state token and returns the full GitHub authorization URL. Using
			// Accept: application/json also instructs the server to append
			// ?format=json to the OAuth callback, so the browser will display
			// the session token as JSON after the user authenticates.
			endpoint, err := url.JoinPath(cfg.ServerURL, "/auth/github")
			if err != nil {
				return fmt.Errorf("building auth URL: %w", err)
			}
			req, err := http.NewRequest("GET", endpoint, nil)
			if err != nil {
				return err
			}
			req.Header.Set("Accept", "application/json")

			resp, err := cliHTTPClient.Do(req)
			if err != nil {
				return fmt.Errorf("connecting to server: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}

			var result struct {
				URL string `json:"url"`
			}
			// Cap the body read so a misconfigured or malicious server can't
			// exhaust memory. Legitimate responses are ~1KB.
			if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&result); err != nil {
				return fmt.Errorf("decoding server response: %w", err)
			}
			if result.URL == "" {
				return fmt.Errorf("server returned empty auth URL")
			}

			// GHP_NO_BROWSER lets tests and CI suppress the side-effect of
			// spawning a browser opener while still exercising the command.
			if os.Getenv("GHP_NO_BROWSER") == "" {
				openBrowser(result.URL)
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Opening browser for GitHub authentication.\n\n")
			fmt.Fprintf(out, "If the browser did not open, visit this URL:\n  %s\n\n", result.URL)
			fmt.Fprintf(out, "After authenticating, the page will display a JSON token.\n")
			fmt.Fprintf(out, "Copy the value of \"session_token\" and save it:\n\n")
			fmt.Fprintf(out, "  ghp auth set-token <session_token>\n\n")
			fmt.Fprintf(out, "Or set the environment variable:\n\n")
			fmt.Fprintf(out, "  export GHP_USER_TOKEN=<session_token>\n")

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
