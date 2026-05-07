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
			appID, _ := cmd.Flags().GetString("app-id")
			appName, _ := cmd.Flags().GetString("app")
			repo, _ := cmd.Flags().GetString("repo")
			repos, _ := cmd.Flags().GetString("repos")
			installationID, _ := cmd.Flags().GetInt64("installation-id")
			installationName, _ := cmd.Flags().GetString("installation")
			scope, _ := cmd.Flags().GetString("scope")
			duration, _ := cmd.Flags().GetString("duration")
			sessionID, _ := cmd.Flags().GetString("session")

			if appName != "" && appID != "" {
				return fmt.Errorf("--app and --app-id are mutually exclusive")
			}
			if installationName != "" && installationID != 0 {
				return fmt.Errorf("--installation and --installation-id are mutually exclusive")
			}

			if appName != "" || installationName != "" {
				if cmd.Flags().Changed("type") && tokenType != "agent" {
					return fmt.Errorf("--app and --installation are only valid for agent tokens (--type agent)")
				}
				tokenType = "agent"
			}

			if appName != "" {
				resolved, err := resolveAppByName(cfg, appName)
				if err != nil {
					return err
				}
				appID = resolved
			}

			if installationName != "" {
				lookupAppID := appID
				if lookupAppID == "" {
					resolved, err := resolveDefaultAppID(cfg)
					if err != nil {
						return err
					}
					lookupAppID = resolved
				}
				resolved, err := resolveInstallationByLogin(cfg, lookupAppID, installationName)
				if err != nil {
					return err
				}
				installationID = resolved
			}

			body := map[string]interface{}{
				"type":     tokenType,
				"scopes":   scope,
				"duration": duration,
			}
			if appID != "" {
				if tokenType != "agent" {
					return fmt.Errorf("--app-id is only valid for agent tokens")
				}
				body["app_record_id"] = appID
			}
			if sessionID != "" {
				body["session_id"] = sessionID
			}

			switch tokenType {
			case "agent":
				if installationID == 0 {
					return fmt.Errorf("--installation or --installation-id is required for agent tokens")
				}
				body["installation_id"] = installationID
				if repos != "" {
					body["repositories"] = strings.Split(repos, ",")
				}
			default:
				if repos != "" {
					body["repositories"] = strings.Split(repos, ",")
				} else if repo != "" {
					body["repository"] = repo
				}
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
	createCmd.Flags().String("type", "proxy", "token type (proxy or agent); inferred as agent when --app or --installation is used")
	createCmd.Flags().String("app-id", "", "database app record ID — selects which GitHub App to use (multi-app mode); omit to use the default app")
	createCmd.Flags().String("app", "", "app name — resolves to app record ID via the server (alternative to --app-id)")
	createCmd.Flags().String("repo", "", "single repository (owner/repo) — omit to allow any repo")
	createCmd.Flags().String("repos", "", "comma-separated repositories — omit to allow any repo; omitting both repos and scope creates an open-scoped token")
	createCmd.Flags().Int64("installation-id", 0, "GitHub App installation ID for agent tokens")
	createCmd.Flags().String("installation", "", "installation account login (e.g., org name) — resolves to installation ID via the server (alternative to --installation-id)")
	createCmd.Flags().String("scope", "", "scopes (e.g., contents:read,pull_requests:write) — omit to allow any permission; omitting both repos and scope creates an open-scoped token")
	createCmd.Flags().String("duration", "24h", `token duration (e.g., "1h", "72h", "never" for no expiry)`)
	createCmd.Flags().String("session", "", "session identifier")

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

type appInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	IsDefault bool   `json:"is_default"`
}

func fetchApps(cfg *cliConfig) ([]appInfo, error) {
	req, err := http.NewRequest("GET", cfg.ServerURL+"/api/apps", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.UserToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp map[string]string
		json.Unmarshal(body, &errResp)
		return nil, fmt.Errorf("failed to list apps: %s", errResp["message"])
	}

	var apps []appInfo
	if err := json.NewDecoder(resp.Body).Decode(&apps); err != nil {
		return nil, fmt.Errorf("decoding apps response: %w", err)
	}
	return apps, nil
}

func resolveAppByName(cfg *cliConfig, name string) (string, error) {
	apps, err := fetchApps(cfg)
	if err != nil {
		return "", err
	}

	for _, app := range apps {
		if strings.EqualFold(app.Name, name) {
			return app.ID, nil
		}
	}

	names := make([]string, len(apps))
	for i, a := range apps {
		names[i] = a.Name
	}
	if len(names) == 0 {
		return "", fmt.Errorf("app %q not found: no apps configured on the server", name)
	}
	return "", fmt.Errorf("app %q not found; available apps: %s", name, strings.Join(names, ", "))
}

func resolveDefaultAppID(cfg *cliConfig) (string, error) {
	apps, err := fetchApps(cfg)
	if err != nil {
		return "", err
	}

	if len(apps) == 0 {
		return "", fmt.Errorf("no apps configured on the server; use --app to specify an app after creating one")
	}
	if len(apps) == 1 {
		return apps[0].ID, nil
	}

	for _, app := range apps {
		if app.IsDefault {
			return app.ID, nil
		}
	}

	names := make([]string, len(apps))
	for i, a := range apps {
		names[i] = a.Name
	}
	return "", fmt.Errorf("multiple apps configured and no default set; use --app to specify one: %s", strings.Join(names, ", "))
}

type installationInfo struct {
	ID      int64 `json:"id"`
	Account struct {
		Login string `json:"login"`
	} `json:"account"`
}

func resolveInstallationByLogin(cfg *cliConfig, appID, login string) (int64, error) {
	req, err := http.NewRequest("GET", cfg.ServerURL+"/api/apps/"+appID+"/installations", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.UserToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("connecting to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp map[string]string
		json.Unmarshal(body, &errResp)
		return 0, fmt.Errorf("failed to list installations: %s", errResp["message"])
	}

	var installations []installationInfo
	if err := json.NewDecoder(resp.Body).Decode(&installations); err != nil {
		return 0, fmt.Errorf("decoding installations response: %w", err)
	}

	for _, inst := range installations {
		if strings.EqualFold(inst.Account.Login, login) {
			return inst.ID, nil
		}
	}

	logins := make([]string, len(installations))
	for i, inst := range installations {
		logins[i] = inst.Account.Login
	}
	if len(logins) == 0 {
		return 0, fmt.Errorf("installation %q not found: app has no installations", login)
	}
	return 0, fmt.Errorf("installation %q not found; available installations: %s", login, strings.Join(logins, ", "))
}
