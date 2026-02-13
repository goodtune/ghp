package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type cliConfig struct {
	ServerURL string `yaml:"server_url"`
	UserToken string `yaml:"user_token"`
}

func loadCLIConfig() (*cliConfig, error) {
	cfg := &cliConfig{}

	// Environment variable overrides.
	cfg.ServerURL = os.Getenv("GHP_SERVER_URL")
	cfg.UserToken = os.Getenv("GHP_USER_TOKEN")

	// Read config file.
	home, err := os.UserHomeDir()
	if err != nil {
		return cfg, nil
	}
	configPath := filepath.Join(home, ".config", "ghp", "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return cfg, nil // File doesn't exist yet, that's ok.
	}

	var fileCfg cliConfig
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return cfg, nil
	}

	// File values are used if env vars are not set.
	if cfg.ServerURL == "" {
		cfg.ServerURL = fileCfg.ServerURL
	}
	if cfg.UserToken == "" {
		cfg.UserToken = fileCfg.UserToken
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

			fmt.Printf("Opening browser for GitHub authentication...\n")
			fmt.Printf("Visit: %s/auth/github\n", cfg.ServerURL)
			fmt.Printf("\nAfter authenticating, run:\n")
			fmt.Printf("  export GHP_USER_TOKEN=<token from callback>\n")

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
				fmt.Println("Not authenticated. Run 'ghp auth login' to authenticate.")
				return nil
			}

			req, err := http.NewRequest("GET", cfg.ServerURL+"/auth/status", nil)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+cfg.UserToken)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("connecting to server: %w", err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)
			var result map[string]interface{}
			json.Unmarshal(body, &result)

			if auth, ok := result["authenticated"].(bool); ok && auth {
				fmt.Printf("Authenticated as: %s\n", result["username"])
				fmt.Printf("Role: %s\n", result["role"])
			} else {
				fmt.Println("Not authenticated or session expired. Run 'ghp auth login'.")
			}

			return nil
		},
	}

	cmd.AddCommand(loginCmd, statusCmd)
	return cmd
}
