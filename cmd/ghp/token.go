package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

func newTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage proxy tokens",
	}

	// token create
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new proxy token",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadCLIConfig()
			if err != nil {
				return err
			}
			if cfg.ServerURL == "" || cfg.UserToken == "" {
				return fmt.Errorf("not configured/authenticated. Set GHP_SERVER_URL and GHP_USER_TOKEN, or run 'ghp auth login'")
			}

			tokenType, _ := cmd.Flags().GetString("type")
			repo, _ := cmd.Flags().GetString("repo")
			repos, _ := cmd.Flags().GetString("repos")
			installationID, _ := cmd.Flags().GetInt64("installation-id")
			scope, _ := cmd.Flags().GetString("scope")
			duration, _ := cmd.Flags().GetString("duration")
			sessionID, _ := cmd.Flags().GetString("session")

			body := map[string]interface{}{
				"type":     tokenType,
				"scopes":   scope,
				"duration": duration,
			}
			if sessionID != "" {
				body["session_id"] = sessionID
			}

			switch tokenType {
			case "agent":
				if repos == "" {
					return fmt.Errorf("--repos is required for agent tokens")
				}
				if installationID == 0 {
					return fmt.Errorf("--installation-id is required for agent tokens")
				}
				body["repositories"] = strings.Split(repos, ",")
				body["installation_id"] = installationID
			default:
				if repo == "" {
					return fmt.Errorf("--repo is required for proxy tokens")
				}
				body["repository"] = repo
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

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Token:        %s\n", result["token"])
			fmt.Fprintf(out, "Type:         %s\n", result["type"])
			if reposList, ok := result["repositories"].([]interface{}); ok && len(reposList) > 0 {
				parts := make([]string, len(reposList))
				for i, r := range reposList {
					parts[i] = fmt.Sprint(r)
				}
				fmt.Fprintf(out, "Repositories: %s\n", strings.Join(parts, ", "))
			}

			if scopes, ok := result["scopes"].(map[string]interface{}); ok {
				parts := make([]string, 0, len(scopes))
				for k, v := range scopes {
					parts = append(parts, fmt.Sprintf("%s:%s", k, v))
				}
				fmt.Fprintf(out, "Scopes:       %s\n", joinStrings(parts, ", "))
			}

			fmt.Fprintf(out, "Expires:      %s\n", result["expires_at"])
			if sid, ok := result["session_id"].(string); ok && sid != "" {
				fmt.Fprintf(out, "Session:      %s\n", sid)
			}

			fmt.Fprintf(out, "\nConfigure your agent:\n")
			fmt.Fprintf(out, "  export GH_TOKEN=%s\n", result["token"])

			return nil
		},
	}
	createCmd.Flags().String("type", "proxy", "token type (proxy or agent)")
	createCmd.Flags().String("repo", "", "repository (owner/repo) for proxy tokens")
	createCmd.Flags().String("repos", "", "comma-separated repositories for agent tokens")
	createCmd.Flags().Int64("installation-id", 0, "GitHub App installation ID for agent tokens")
	createCmd.Flags().String("scope", "", "scopes (e.g., contents:read,pull_requests:write)")
	createCmd.Flags().String("duration", "24h", "token duration")
	createCmd.Flags().String("session", "", "session identifier")
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
				fmt.Fprintln(cmd.OutOrStdout(), "No tokens found.")
				return nil
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tTYPE\tREPOS\tSCOPES\tSESSION\tEXPIRES\tREQUESTS")
			for _, t := range tokens {
				prefix := fmt.Sprint(t["token_prefix"])
				tokenType := fmt.Sprint(t["token_type"])

				reposStr := ""
				if reposList, ok := t["repositories"].([]interface{}); ok {
					parts := make([]string, len(reposList))
					for i, r := range reposList {
						parts[i] = fmt.Sprint(r)
					}
					reposStr = strings.Join(parts, ",")
				}

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

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					prefix, tokenType, reposStr, scopeStr, session, expiresStr, requests)
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
				fmt.Fprintf(cmd.OutOrStdout(), "Token %s revoked.\n", tokenID)
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
