package config

import (
	"strings"
	"testing"
)

func TestValidate_TableDriven(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string // empty means no error expected
	}{
		{
			name: "valid non-vault",
			cfg: Config{
				GitHub: GitHubConfig{
					ClientID:     "cid",
					ClientSecret: "csec",
				},
				EncryptionKey: "abc123",
			},
			wantErr: "",
		},
		{
			name: "vault missing addr",
			cfg: Config{
				Vault: VaultConfig{
					Enabled:  true,
					RoleID:   "r",
					SecretID: "s",
				},
			},
			wantErr: "vault.addr is required",
		},
		{
			name: "vault missing role_id",
			cfg: Config{
				Vault: VaultConfig{
					Enabled:  true,
					Addr:     "https://vault:8200",
					SecretID: "s",
				},
			},
			wantErr: "vault.role_id is required",
		},
		{
			name: "vault missing secret_id",
			cfg: Config{
				Vault: VaultConfig{
					Enabled: true,
					Addr:    "https://vault:8200",
					RoleID:  "r",
				},
			},
			wantErr: "vault.secret_id is required",
		},
		{
			name: "vault with local encryption_key",
			cfg: Config{
				Vault: VaultConfig{
					Enabled:  true,
					Addr:     "https://vault:8200",
					RoleID:   "r",
					SecretID: "s",
				},
				EncryptionKey: "should-not-be-here",
			},
			wantErr: "encryption_key must not be set",
		},
		{
			name: "vault with local client_id",
			cfg: Config{
				Vault: VaultConfig{
					Enabled:  true,
					Addr:     "https://vault:8200",
					RoleID:   "r",
					SecretID: "s",
				},
				GitHub: GitHubConfig{ClientID: "local-cid"},
			},
			wantErr: "github.client_id",
		},
		{
			name: "vault with local enterprise_slug",
			cfg: Config{
				Vault: VaultConfig{
					Enabled:  true,
					Addr:     "https://vault:8200",
					RoleID:   "r",
					SecretID: "s",
				},
				GitHub: GitHubConfig{EnterpriseSlug: "my-enterprise"},
			},
			wantErr: "enterprise_slug",
		},
		{
			name: "valid vault config",
			cfg: Config{
				Vault: VaultConfig{
					Enabled:  true,
					Addr:     "https://vault:8200",
					RoleID:   "r",
					SecretID: "s",
				},
			},
			wantErr: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}
