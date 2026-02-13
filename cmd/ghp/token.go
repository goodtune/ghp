package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

func newTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage ghp proxy tokens",
	}

	// token create
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new ghp_ token",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.ServerURL == "" || cfg.UserToken == "" {
				return fmt.Errorf("not configured/authenticated. Set GHP_SERVER_URL and GHP_USER_TOKEN, or run 'ghp auth login'")
			}

			repo, _ := cmd.Flags().GetString("repo")
			scope, _ := cmd.Flags().GetString("scope")
			duration, _ := cmd.Flags().GetString("duration")
			sessionID, _ := cmd.Flags().GetString("session")

			body := map[string]string{
				"repository": repo,
				"scopes":     scope,
				"duration":   duration,
				"session_id": sessionID,
			}
			jsonBody, _ := json.Marshal(body)

			req, err := http.NewRequest("POST", cfg.ServerURL+"/api/tokens", bytes.NewReader(jsonBody))
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+cfg.UserToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("connecting to server: %w", err)
			}
			defer resp.Body.Close()

			respBody, _ := io.ReadAll(resp.Body)
			var result map[string]interface{}
			json.Unmarshal(respBody, &result)

			if resp.StatusCode != http.StatusCreated {
				return fmt.Errorf("failed: %s", result["message"])
			}

			fmt.Printf("Token:      %s\n", result["token"])
			fmt.Printf("Repository: %s\n", result["repository"])

			if scopes, ok := result["scopes"].(map[string]interface{}); ok {
				parts := make([]string, 0, len(scopes))
				for k, v := range scopes {
					parts = append(parts, fmt.Sprintf("%s:%s", k, v))
				}
				fmt.Printf("Scopes:     %s\n", joinStrings(parts, ", "))
			}

			fmt.Printf("Expires:    %s\n", result["expires_at"])
			if sid, ok := result["session_id"].(string); ok && sid != "" {
				fmt.Printf("Session:    %s\n", sid)
			}

			fmt.Printf("\nConfigure your agent:\n")
			fmt.Printf("  export GH_TOKEN=%s\n", result["token"])

			serverHost := cfg.ServerURL
			// Strip protocol.
			for _, prefix := range []string{"https://", "http://"} {
				if len(serverHost) > len(prefix) && serverHost[:len(prefix)] == prefix {
					serverHost = serverHost[len(prefix):]
					break
				}
			}
			fmt.Printf("  export GH_HOST=%s\n", serverHost)

			return nil
		},
	}
	createCmd.Flags().String("repo", "", "repository (owner/repo)")
	createCmd.Flags().String("scope", "", "scopes (e.g., contents:read,pulls:write)")
	createCmd.Flags().String("duration", "24h", "token duration")
	createCmd.Flags().String("session", "", "session identifier")
	createCmd.MarkFlagRequired("repo")
	createCmd.MarkFlagRequired("scope")

	// token list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List active tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.ServerURL == "" || cfg.UserToken == "" {
				return fmt.Errorf("not configured/authenticated")
			}

			req, err := http.NewRequest("GET", cfg.ServerURL+"/api/tokens", nil)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+cfg.UserToken)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("connecting to server: %w", err)
			}
			defer resp.Body.Close()

			var tokens []map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&tokens)

			if len(tokens) == 0 {
				fmt.Println("No tokens found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tREPO\tSCOPES\tSESSION\tEXPIRES\tREQUESTS")
			for _, t := range tokens {
				prefix := fmt.Sprint(t["token_prefix"])
				repo := fmt.Sprint(t["repository"])
				session := fmt.Sprint(t["session_id"])
				if session == "" {
					session = "-"
				}

				scopeStr := ""
				if scopes, ok := t["scopes"].(map[string]interface{}); ok {
					parts := make([]string, 0, len(scopes))
					for k, v := range scopes {
						parts = append(parts, fmt.Sprintf("%s:%s", k, v))
					}
					scopeStr = joinStrings(parts, ",")
				} else {
					scopeStr = fmt.Sprint(t["scopes"])
				}

				expiresStr := ""
				if exp, ok := t["expires_at"].(string); ok {
					if ts, err := time.Parse(time.RFC3339, exp); err == nil {
						expiresStr = ts.Format("2006-01-02 15:04")
					} else {
						expiresStr = exp
					}
				}

				requests := "0"
				if n, ok := t["request_count"].(float64); ok {
					requests = fmt.Sprintf("%.0f", n)
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					prefix, repo, scopeStr, session, expiresStr, requests)
			}
			w.Flush()
			return nil
		},
	}

	// token revoke
	revokeCmd := &cobra.Command{
		Use:   "revoke <token-id>",
		Short: "Revoke a token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.ServerURL == "" || cfg.UserToken == "" {
				return fmt.Errorf("not configured/authenticated")
			}

			tokenID := args[0]

			req, err := http.NewRequest("DELETE", cfg.ServerURL+"/api/tokens/"+tokenID, nil)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+cfg.UserToken)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("connecting to server: %w", err)
			}
			defer resp.Body.Close()

			var result map[string]string
			json.NewDecoder(resp.Body).Decode(&result)

			if resp.StatusCode == http.StatusOK {
				fmt.Printf("Token %s revoked.\n", tokenID)
			} else {
				return fmt.Errorf("failed: %s", result["message"])
			}
			return nil
		},
	}

	cmd.AddCommand(createCmd, listCmd, revokeCmd)
	return cmd
}

func joinStrings(parts []string, sep string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += sep
		}
		result += p
	}
	return result
}
