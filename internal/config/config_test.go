package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadAdminsFromEnv(t *testing.T) {
	t.Setenv("GHP_ADMINS", "alice, bob , charlie")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alice", "bob", "charlie"}
	if len(cfg.Admins) != len(want) {
		t.Fatalf("expected %d admins, got %d: %v", len(want), len(cfg.Admins), cfg.Admins)
	}
	for i, w := range want {
		if cfg.Admins[i] != w {
			t.Errorf("Admins[%d] = %q, want %q", i, cfg.Admins[i], w)
		}
	}
}

func TestLoadEnterpriseExceptionsFromYAML(t *testing.T) {
	yaml := `
github:
  enterprise_slug: "12345"
  enterprise_exceptions:
    - match:
        - torvalds
        - kubernetes/website
      teams:
        - acme-org/oss-contributors
      identity:
        app_record_id: "9f3c2a1e-0000-0000-0000-000000000000"
    - match:
        - partner
`
	path := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GitHub.EnterpriseSlug != "12345" {
		t.Errorf("EnterpriseSlug = %q, want %q", cfg.GitHub.EnterpriseSlug, "12345")
	}
	if len(cfg.GitHub.EnterpriseExceptions) != 2 {
		t.Fatalf("expected 2 exceptions, got %d", len(cfg.GitHub.EnterpriseExceptions))
	}
	first := cfg.GitHub.EnterpriseExceptions[0]
	if len(first.Match) != 2 || first.Match[0] != "torvalds" || first.Match[1] != "kubernetes/website" {
		t.Errorf("unexpected match entries: %v", first.Match)
	}
	if len(first.Teams) != 1 || first.Teams[0] != "acme-org/oss-contributors" {
		t.Errorf("unexpected teams entries: %v", first.Teams)
	}
	if first.Identity.AppRecordID != "9f3c2a1e-0000-0000-0000-000000000000" {
		t.Errorf("unexpected app_record_id: %q", first.Identity.AppRecordID)
	}
	second := cfg.GitHub.EnterpriseExceptions[1]
	if len(second.Match) != 1 || second.Match[0] != "partner" {
		t.Errorf("unexpected match entries: %v", second.Match)
	}
	if second.Identity.AppRecordID != "" {
		t.Errorf("expected empty app_record_id, got %q", second.Identity.AppRecordID)
	}
}

func TestLoadAllowedRedirectsFromEnv(t *testing.T) {
	t.Setenv("GHP_AUTH_ALLOWED_REDIRECTS", "https://a.example.com/cb,*.internal.example.com")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://a.example.com/cb", "*.internal.example.com"}
	if len(cfg.Auth.AllowedRedirects) != len(want) {
		t.Fatalf("expected %d redirects, got %d: %v", len(want), len(cfg.Auth.AllowedRedirects), cfg.Auth.AllowedRedirects)
	}
	for i, w := range want {
		if cfg.Auth.AllowedRedirects[i] != w {
			t.Errorf("AllowedRedirects[%d] = %q, want %q", i, cfg.Auth.AllowedRedirects[i], w)
		}
	}
}

func TestLoadBlockGithubPatFromEnv(t *testing.T) {
	t.Setenv("GHP_BLOCK_GITHUB_PAT", "true")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Block.GithubPat {
		t.Error("expected Block.GithubPat to be true")
	}
	if !cfg.IsTokenBlocked("github_pat_11ABCDEF0123456789") {
		t.Error("expected fine-grained PAT to be blocked")
	}
	if cfg.IsTokenBlocked("ghp_classic123") {
		t.Error("blocking github_pat_ must not block classic ghp_ tokens")
	}
}

func TestIsTokenBlocked_GithubPatDisabledByDefault(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IsTokenBlocked("github_pat_11ABCDEF0123456789") {
		t.Error("fine-grained PATs must not be blocked by default")
	}
}

func TestLoadTLSCertFromEnv(t *testing.T) {
	t.Setenv("GHP_TLS_CERT_FILE", "/tmp/test.crt")
	t.Setenv("GHP_TLS_KEY_FILE", "/tmp/test.key")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TLS.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(cfg.TLS.Certificates))
	}
	if cfg.TLS.Certificates[0].CertFile != "/tmp/test.crt" {
		t.Errorf("CertFile = %q, want /tmp/test.crt", cfg.TLS.Certificates[0].CertFile)
	}
	if cfg.TLS.Certificates[0].KeyFile != "/tmp/test.key" {
		t.Errorf("KeyFile = %q, want /tmp/test.key", cfg.TLS.Certificates[0].KeyFile)
	}
}

func TestLoadTLSCertFromEnvPartial(t *testing.T) {
	// Only cert, no key — should not populate the slice.
	t.Setenv("GHP_TLS_CERT_FILE", "/tmp/test.crt")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TLS.Certificates) != 0 {
		t.Fatalf("expected 0 certificates when only cert is set, got %d", len(cfg.TLS.Certificates))
	}
}

func TestLoadBlockFromEnv(t *testing.T) {
	t.Setenv("GHP_BLOCK_GHO", "true")
	t.Setenv("GHP_BLOCK_GHU", "true")
	t.Setenv("GHP_BLOCK_GHS", "true")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Block.GHO != true {
		t.Error("expected Block.GHO to be true")
	}
	if cfg.Block.GHU != true {
		t.Error("expected Block.GHU to be true")
	}
	if cfg.Block.GHS != true {
		t.Error("expected Block.GHS to be true")
	}
	// These were not set.
	if cfg.Block.GHP != false {
		t.Error("expected Block.GHP to be false")
	}
	if cfg.Block.GHR != false {
		t.Error("expected Block.GHR to be false")
	}
}

func TestLoadReleasesFromEnv(t *testing.T) {
	t.Setenv("GHP_RELEASES_MODE", "block")
	t.Setenv("GHP_RELEASES_REDIRECT_TO", "https://releases.example.com/")
	t.Setenv("GHP_RELEASES_ALLOW", "org/repo,goodtune")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Releases.Mode != "block" {
		t.Errorf("Mode = %q, want %q", cfg.Releases.Mode, "block")
	}
	if cfg.Releases.RedirectTo != "https://releases.example.com/" {
		t.Errorf("RedirectTo = %q, want %q", cfg.Releases.RedirectTo, "https://releases.example.com/")
	}
	want := []string{"org/repo", "goodtune"}
	if len(cfg.Releases.Allow) != len(want) {
		t.Fatalf("Allow = %v, want %v", cfg.Releases.Allow, want)
	}
	for i, w := range want {
		if cfg.Releases.Allow[i] != w {
			t.Errorf("Allow[%d] = %q, want %q", i, cfg.Releases.Allow[i], w)
		}
	}
}

func TestLoadReleasesRedirectToEnv(t *testing.T) {
	t.Setenv("GHP_RELEASES_REDIRECT_TO", "https://alt.example.com/")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Releases.RedirectTo != "https://alt.example.com/" {
		t.Errorf("RedirectTo = %q, want %q", cfg.Releases.RedirectTo, "https://alt.example.com/")
	}
}

func TestLoadReleasesAllowIndexed(t *testing.T) {
	t.Setenv("GHP_RELEASES_MODE", "block")
	t.Setenv("GHP_RELEASES_ALLOW_COUNT", "2")
	t.Setenv("GHP_RELEASES_ALLOW_0", "org/repo")
	t.Setenv("GHP_RELEASES_ALLOW_1", "goodtune")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"org/repo", "goodtune"}
	if len(cfg.Releases.Allow) != len(want) {
		t.Fatalf("Allow = %v, want %v", cfg.Releases.Allow, want)
	}
	for i, w := range want {
		if cfg.Releases.Allow[i] != w {
			t.Errorf("Allow[%d] = %q, want %q", i, cfg.Releases.Allow[i], w)
		}
	}
}

func TestLoadReleasesAllowIndexedMissingEntry(t *testing.T) {
	t.Setenv("GHP_RELEASES_ALLOW_COUNT", "2")
	t.Setenv("GHP_RELEASES_ALLOW_0", "org/repo")
	// GHP_RELEASES_ALLOW_1 is intentionally not set.

	_, err := Load("")
	if err == nil {
		t.Fatal("expected error for missing indexed allow entry, got nil")
	}
}

func TestLoadReleasesAllowIndexedBadCount(t *testing.T) {
	t.Setenv("GHP_RELEASES_ALLOW_COUNT", "notanumber")

	_, err := Load("")
	if err == nil {
		t.Fatal("expected error for invalid GHP_RELEASES_ALLOW_COUNT, got nil")
	}
}

func TestLoadReleasesAllowIndexedNegativeCount(t *testing.T) {
	t.Setenv("GHP_RELEASES_ALLOW_COUNT", "-1")

	_, err := Load("")
	if err == nil {
		t.Fatal("expected error for negative GHP_RELEASES_ALLOW_COUNT, got nil")
	}
}

func TestLoadReleasesAllowIndexedOverridesEnv(t *testing.T) {
	// Indexed entries should take precedence over the comma-separated env var.
	t.Setenv("GHP_RELEASES_ALLOW", "yaml-org")
	t.Setenv("GHP_RELEASES_ALLOW_COUNT", "1")
	t.Setenv("GHP_RELEASES_ALLOW_0", "indexed-org")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Releases.Allow) != 1 || cfg.Releases.Allow[0] != "indexed-org" {
		t.Errorf("Allow = %v, want [indexed-org]", cfg.Releases.Allow)
	}
}

func TestIsReleaseAllowed(t *testing.T) {
	tests := []struct {
		name    string
		allow   []string
		org     string
		repo    string
		allowed bool
	}{
		{name: "org match", allow: []string{"goodtune"}, org: "goodtune", repo: "ghp", allowed: true},
		{name: "org/repo match", allow: []string{"goodtune/ghp"}, org: "goodtune", repo: "ghp", allowed: true},
		{name: "org no match", allow: []string{"other"}, org: "goodtune", repo: "ghp", allowed: false},
		{name: "org/repo no match different repo", allow: []string{"goodtune/other"}, org: "goodtune", repo: "ghp", allowed: false},
		{name: "case insensitive org", allow: []string{"GoodTune"}, org: "goodtune", repo: "ghp", allowed: true},
		{name: "case insensitive org/repo", allow: []string{"GoodTune/GHP"}, org: "goodtune", repo: "ghp", allowed: true},
		{name: "empty allow list", allow: nil, org: "goodtune", repo: "ghp", allowed: false},
		{name: "multiple entries second matches", allow: []string{"other", "goodtune"}, org: "goodtune", repo: "ghp", allowed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Releases: ReleasesConfig{Allow: tt.allow}}
			got := cfg.IsReleaseAllowed(tt.org, tt.repo)
			if got != tt.allowed {
				t.Errorf("IsReleaseAllowed(%q, %q) = %v, want %v", tt.org, tt.repo, got, tt.allowed)
			}
		})
	}
}

func TestLoadCodeloadFromEnv(t *testing.T) {
	t.Setenv("GHP_CODELOAD_REDIRECT_TO", "https://codeload.cache.example.com/")
	t.Setenv("GHP_CODELOAD_ALLOW", "actions,goodtune/ghp")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Codeload.RedirectTo != "https://codeload.cache.example.com/" {
		t.Errorf("RedirectTo = %q, want %q", cfg.Codeload.RedirectTo, "https://codeload.cache.example.com/")
	}
	want := []string{"actions", "goodtune/ghp"}
	if len(cfg.Codeload.Allow) != len(want) {
		t.Fatalf("Allow = %v, want %v", cfg.Codeload.Allow, want)
	}
	for i, w := range want {
		if cfg.Codeload.Allow[i] != w {
			t.Errorf("Allow[%d] = %q, want %q", i, cfg.Codeload.Allow[i], w)
		}
	}
}

func TestLoadCodeloadAllowIndexed(t *testing.T) {
	t.Setenv("GHP_CODELOAD_ALLOW_COUNT", "2")
	t.Setenv("GHP_CODELOAD_ALLOW_0", "goodtune/ghp")
	t.Setenv("GHP_CODELOAD_ALLOW_1", "actions")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"goodtune/ghp", "actions"}
	if len(cfg.Codeload.Allow) != len(want) {
		t.Fatalf("Allow = %v, want %v", cfg.Codeload.Allow, want)
	}
	for i, w := range want {
		if cfg.Codeload.Allow[i] != w {
			t.Errorf("Allow[%d] = %q, want %q", i, cfg.Codeload.Allow[i], w)
		}
	}
}

func TestLoadCodeloadAllowIndexedMissingEntry(t *testing.T) {
	t.Setenv("GHP_CODELOAD_ALLOW_COUNT", "2")
	t.Setenv("GHP_CODELOAD_ALLOW_0", "actions")
	// GHP_CODELOAD_ALLOW_1 is intentionally not set.

	if _, err := Load(""); err == nil {
		t.Fatal("expected error for missing indexed allow entry, got nil")
	}
}

func TestLoadCodeloadAllowIndexedBadCount(t *testing.T) {
	t.Setenv("GHP_CODELOAD_ALLOW_COUNT", "notanumber")

	if _, err := Load(""); err == nil {
		t.Fatal("expected error for invalid GHP_CODELOAD_ALLOW_COUNT, got nil")
	}
}

func TestLoadCodeloadAllowIndexedNegativeCount(t *testing.T) {
	t.Setenv("GHP_CODELOAD_ALLOW_COUNT", "-1")

	if _, err := Load(""); err == nil {
		t.Fatal("expected error for negative GHP_CODELOAD_ALLOW_COUNT, got nil")
	}
}

func TestLoadCodeloadAllowIndexedOverridesEnv(t *testing.T) {
	// Indexed entries should take precedence over the comma-separated env var.
	t.Setenv("GHP_CODELOAD_ALLOW", "yaml-org")
	t.Setenv("GHP_CODELOAD_ALLOW_COUNT", "1")
	t.Setenv("GHP_CODELOAD_ALLOW_0", "indexed-org")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Codeload.Allow) != 1 || cfg.Codeload.Allow[0] != "indexed-org" {
		t.Errorf("Allow = %v, want [indexed-org]", cfg.Codeload.Allow)
	}
}

func TestIsCodeloadAllowed(t *testing.T) {
	tests := []struct {
		name    string
		allow   []string
		org     string
		repo    string
		allowed bool
	}{
		{name: "org match", allow: []string{"actions"}, org: "actions", repo: "checkout", allowed: true},
		{name: "org/repo match", allow: []string{"actions/checkout"}, org: "actions", repo: "checkout", allowed: true},
		{name: "org no match", allow: []string{"other"}, org: "actions", repo: "checkout", allowed: false},
		{name: "org/repo no match different repo", allow: []string{"actions/setup-node"}, org: "actions", repo: "checkout", allowed: false},
		{name: "case insensitive org", allow: []string{"ACTIONS"}, org: "actions", repo: "checkout", allowed: true},
		{name: "case insensitive org/repo", allow: []string{"Actions/Checkout"}, org: "actions", repo: "checkout", allowed: true},
		{name: "empty allow list", allow: nil, org: "actions", repo: "checkout", allowed: false},
		{name: "multiple entries second matches", allow: []string{"other", "actions"}, org: "actions", repo: "checkout", allowed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Codeload: CodeloadConfig{Allow: tt.allow}}
			got := cfg.IsCodeloadAllowed(tt.org, tt.repo)
			if got != tt.allowed {
				t.Errorf("IsCodeloadAllowed(%q, %q) = %v, want %v", tt.org, tt.repo, got, tt.allowed)
			}
		})
	}
}

func TestIsTokenBlocked(t *testing.T) {
	tests := []struct {
		name    string
		block   BlockConfig
		token   string
		blocked bool
	}{
		{name: "ghp blocked", block: BlockConfig{GHP: true}, token: "ghp_abc123", blocked: true},
		{name: "gho blocked", block: BlockConfig{GHO: true}, token: "gho_abc123", blocked: true},
		{name: "ghu blocked", block: BlockConfig{GHU: true}, token: "ghu_abc123", blocked: true},
		{name: "ghs blocked", block: BlockConfig{GHS: true}, token: "ghs_abc123", blocked: true},
		{name: "ghr blocked", block: BlockConfig{GHR: true}, token: "ghr_abc123", blocked: true},
		{name: "gho not blocked", block: BlockConfig{}, token: "gho_abc123", blocked: false},
		{name: "ghp not blocked", block: BlockConfig{}, token: "ghp_abc123", blocked: false},
		{name: "ghx never blocked", block: BlockConfig{GHP: true, GHO: true}, token: "ghx_abc123", blocked: false},
		{name: "gha never blocked", block: BlockConfig{GHP: true, GHO: true}, token: "gha_abc123", blocked: false},
		{name: "unknown prefix", block: BlockConfig{GHP: true}, token: "xyz_abc123", blocked: false},
		{name: "empty token", block: BlockConfig{GHP: true}, token: "", blocked: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Block: tt.block}
			got := cfg.IsTokenBlocked(tt.token)
			if got != tt.blocked {
				t.Errorf("IsTokenBlocked(%q) = %v, want %v", tt.token, got, tt.blocked)
			}
		})
	}
}

func TestLoadBlockAnonymousGitFromEnv(t *testing.T) {
	t.Setenv("GHP_BLOCK_ANONYMOUS_GIT", "true")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Block.AnonymousGit {
		t.Error("expected Block.AnonymousGit to be true")
	}
}

func TestLoadBlockAnonymousGitFromYAML(t *testing.T) {
	f, err := os.CreateTemp("", "ghp-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString("block:\n  anonymous_git: true\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Block.AnonymousGit {
		t.Error("expected Block.AnonymousGit to be true when set in YAML")
	}
}

func TestVaultAuthDefaults(t *testing.T) {
	// Assert against Defaults() rather than Load("") so ambient
	// GHP_DATABASE_VAULT_* environment variables on a developer or CI
	// machine cannot mask a regression in the documented defaults.
	cfg := Defaults()
	if got, want := cfg.Database.VaultAuthMethod, "approle"; got != want {
		t.Errorf("VaultAuthMethod default = %q, want %q", got, want)
	}
	if got, want := cfg.Database.VaultK8sMount, "kubernetes"; got != want {
		t.Errorf("VaultK8sMount default = %q, want %q", got, want)
	}
	if got, want := cfg.Database.VaultK8sTokenPath, "/var/run/secrets/kubernetes.io/serviceaccount/token"; got != want {
		t.Errorf("VaultK8sTokenPath default = %q, want %q", got, want)
	}
}

func TestLoadVaultK8sFromEnv(t *testing.T) {
	t.Setenv("GHP_DATABASE_VAULT_AUTH_METHOD", "kubernetes")
	t.Setenv("GHP_DATABASE_VAULT_K8S_ROLE", "ghp")
	t.Setenv("GHP_DATABASE_VAULT_K8S_MOUNT", "kubernetes/sin-common-apps-1")
	t.Setenv("GHP_DATABASE_VAULT_K8S_TOKEN_PATH", "/run/secrets/projected/token")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.VaultAuthMethod != "kubernetes" {
		t.Errorf("VaultAuthMethod = %q, want kubernetes", cfg.Database.VaultAuthMethod)
	}
	if cfg.Database.VaultK8sRole != "ghp" {
		t.Errorf("VaultK8sRole = %q, want ghp", cfg.Database.VaultK8sRole)
	}
	if cfg.Database.VaultK8sMount != "kubernetes/sin-common-apps-1" {
		t.Errorf("VaultK8sMount = %q, want kubernetes/sin-common-apps-1", cfg.Database.VaultK8sMount)
	}
	if cfg.Database.VaultK8sTokenPath != "/run/secrets/projected/token" {
		t.Errorf("VaultK8sTokenPath = %q, want /run/secrets/projected/token", cfg.Database.VaultK8sTokenPath)
	}
}

func TestLoadClientIPHeaderFromEnv(t *testing.T) {
	t.Setenv("GHP_SERVER_CLIENT_IP_HEADER", "X-Forwarded-For")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.ClientIPHeader != "x-forwarded-for" {
		t.Errorf("ClientIPHeader = %q, want %q", cfg.Server.ClientIPHeader, "x-forwarded-for")
	}
}

func TestLoadClientIPHeaderDefaultsEmpty(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.ClientIPHeader != "" {
		t.Errorf("ClientIPHeader = %q, want empty", cfg.Server.ClientIPHeader)
	}
}

func TestLoadClientIPHeaderInvalid(t *testing.T) {
	t.Setenv("GHP_SERVER_CLIENT_IP_HEADER", "cf-connecting-ip")

	if _, err := Load(""); err == nil {
		t.Fatal("expected error for unsupported client_ip_header")
	}
}

type warnRecorder struct {
	messages []string
}

func (w *warnRecorder) Warn(msg string, args ...any) {
	w.messages = append(w.messages, msg)
}

func TestWarnMissingClientIPHeader(t *testing.T) {
	tests := []struct {
		name              string
		trustProxyHeaders bool
		clientIPHeader    string
		wantWarn          bool
	}{
		{name: "trust set without client ip header warns", trustProxyHeaders: true, wantWarn: true},
		{name: "trust set with client ip header", trustProxyHeaders: true, clientIPHeader: "x-forwarded-for"},
		{name: "trust unset without client ip header"},
		{name: "trust unset with client ip header", clientIPHeader: "x-forwarded-for"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Server: ServerConfig{
				TrustProxyHeaders: tt.trustProxyHeaders,
				ClientIPHeader:    tt.clientIPHeader,
			}}
			rec := &warnRecorder{}
			cfg.WarnMissingClientIPHeader(rec)
			if got := len(rec.messages) > 0; got != tt.wantWarn {
				t.Errorf("warned = %v, want %v (messages: %v)", got, tt.wantWarn, rec.messages)
			}
		})
	}
}

func TestLoadForwardProxyAllowRequestHeaderFromEnv(t *testing.T) {
	t.Setenv("GHP_FORWARD_PROXY_ALLOW_REQUEST_HEADER", "true")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ForwardProxy.AllowRequestHeader {
		t.Error("expected ForwardProxy.AllowRequestHeader to be true")
	}
}

func TestForwardProxyAllowRequestHeaderDefaultsFalse(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ForwardProxy.AllowRequestHeader {
		t.Error("expected ForwardProxy.AllowRequestHeader to default to false")
	}
}

func TestWebhooksDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	w := cfg.Webhooks
	if w.Enabled {
		t.Error("Webhooks.Enabled should default to false")
	}
	if w.Path != "/webhooks/github" {
		t.Errorf("Path = %q, want /webhooks/github", w.Path)
	}
	if w.MaxPayloadBytes != 25*1024*1024 {
		t.Errorf("MaxPayloadBytes = %d, want %d", w.MaxPayloadBytes, 25*1024*1024)
	}
	if w.NATS.StoreDir != "nats" {
		t.Errorf("NATS.StoreDir = %q, want nats", w.NATS.StoreDir)
	}
	if w.NATS.Stream != "GITHUB_WEBHOOKS" {
		t.Errorf("NATS.Stream = %q, want GITHUB_WEBHOOKS", w.NATS.Stream)
	}
	if w.NATS.SubjectPrefix != "github.webhooks" {
		t.Errorf("NATS.SubjectPrefix = %q, want github.webhooks", w.NATS.SubjectPrefix)
	}
	if w.NATS.MaxAge != 7*24*time.Hour {
		t.Errorf("NATS.MaxAge = %v, want 168h", w.NATS.MaxAge)
	}
	if w.NATS.MaxBytes != 1<<30 {
		t.Errorf("NATS.MaxBytes = %d, want %d", w.NATS.MaxBytes, 1<<30)
	}
	if w.NATS.DedupeWindow != 10*time.Minute {
		t.Errorf("NATS.DedupeWindow = %v, want 10m", w.NATS.DedupeWindow)
	}
	if w.NATS.Listen != "" {
		t.Errorf("NATS.Listen = %q, want empty", w.NATS.Listen)
	}
	if w.Ngrok.Enabled {
		t.Error("Ngrok.Enabled should default to false")
	}
}

func TestLoadWebhooksFromEnv(t *testing.T) {
	t.Setenv("GHP_WEBHOOKS_ENABLED", "true")
	t.Setenv("GHP_WEBHOOKS_PATH", "/hooks/gh")
	t.Setenv("GHP_WEBHOOKS_SECRET", "global-secret")
	t.Setenv("GHP_WEBHOOKS_MAX_PAYLOAD_BYTES", "1024")
	t.Setenv("GHP_WEBHOOKS_NATS_LISTEN", "127.0.0.1:4222")
	t.Setenv("GHP_WEBHOOKS_NATS_AUTH_TOKEN", "tok")
	t.Setenv("GHP_WEBHOOKS_NATS_TLS", "true")
	t.Setenv("GHP_WEBHOOKS_NATS_STORE_DIR", "/var/lib/ghp/nats")
	t.Setenv("GHP_WEBHOOKS_NATS_STREAM", "HOOKS")
	t.Setenv("GHP_WEBHOOKS_NATS_SUBJECT_PREFIX", "gh.hooks")
	t.Setenv("GHP_WEBHOOKS_NATS_MAX_AGE", "48h")
	t.Setenv("GHP_WEBHOOKS_NATS_MAX_BYTES", "2048")
	t.Setenv("GHP_WEBHOOKS_NATS_DEDUPE_WINDOW", "5m")
	t.Setenv("GHP_WEBHOOKS_NGROK_ENABLED", "true")
	t.Setenv("GHP_WEBHOOKS_NGROK_AUTHTOKEN", "ngrok-token")
	t.Setenv("GHP_WEBHOOKS_NGROK_DOMAIN", "hooks.example.ngrok.app")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	w := cfg.Webhooks
	if !w.Enabled {
		t.Error("Enabled = false, want true")
	}
	if w.Path != "/hooks/gh" {
		t.Errorf("Path = %q", w.Path)
	}
	if w.Secret != "global-secret" {
		t.Errorf("Secret = %q", w.Secret)
	}
	if w.MaxPayloadBytes != 1024 {
		t.Errorf("MaxPayloadBytes = %d", w.MaxPayloadBytes)
	}
	if w.NATS.Listen != "127.0.0.1:4222" {
		t.Errorf("NATS.Listen = %q", w.NATS.Listen)
	}
	if w.NATS.AuthToken != "tok" {
		t.Errorf("NATS.AuthToken = %q", w.NATS.AuthToken)
	}
	if !w.NATS.TLS {
		t.Error("NATS.TLS = false, want true")
	}
	if w.NATS.StoreDir != "/var/lib/ghp/nats" {
		t.Errorf("NATS.StoreDir = %q", w.NATS.StoreDir)
	}
	if w.NATS.Stream != "HOOKS" {
		t.Errorf("NATS.Stream = %q", w.NATS.Stream)
	}
	if w.NATS.SubjectPrefix != "gh.hooks" {
		t.Errorf("NATS.SubjectPrefix = %q", w.NATS.SubjectPrefix)
	}
	if w.NATS.MaxAge != 48*time.Hour {
		t.Errorf("NATS.MaxAge = %v", w.NATS.MaxAge)
	}
	if w.NATS.MaxBytes != 2048 {
		t.Errorf("NATS.MaxBytes = %d", w.NATS.MaxBytes)
	}
	if w.NATS.DedupeWindow != 5*time.Minute {
		t.Errorf("NATS.DedupeWindow = %v", w.NATS.DedupeWindow)
	}
	if !w.Ngrok.Enabled {
		t.Error("Ngrok.Enabled = false, want true")
	}
	if w.Ngrok.Authtoken != "ngrok-token" {
		t.Errorf("Ngrok.Authtoken = %q", w.Ngrok.Authtoken)
	}
	if w.Ngrok.Domain != "hooks.example.ngrok.app" {
		t.Errorf("Ngrok.Domain = %q", w.Ngrok.Domain)
	}
}

func TestLoadWebhooksFromYAML(t *testing.T) {
	yaml := `
webhooks:
  enabled: true
  path: /gh
  nats:
    listen: ":4222"
    subject_prefix: "gh"
  ngrok:
    enabled: true
    domain: "example.ngrok.app"
`
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(yaml); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Webhooks.Enabled || cfg.Webhooks.Path != "/gh" {
		t.Errorf("unexpected webhooks config: %+v", cfg.Webhooks)
	}
	if cfg.Webhooks.NATS.Listen != ":4222" || cfg.Webhooks.NATS.SubjectPrefix != "gh" {
		t.Errorf("unexpected nats config: %+v", cfg.Webhooks.NATS)
	}
	// Unset YAML keys keep their defaults.
	if cfg.Webhooks.NATS.Stream != "GITHUB_WEBHOOKS" {
		t.Errorf("Stream = %q, want default", cfg.Webhooks.NATS.Stream)
	}
	if !cfg.Webhooks.Ngrok.Enabled || cfg.Webhooks.Ngrok.Domain != "example.ngrok.app" {
		t.Errorf("unexpected ngrok config: %+v", cfg.Webhooks.Ngrok)
	}
}

func TestWebhooksValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*WebhooksConfig)
		wantErr bool
	}{
		{"disabled is always valid", func(w *WebhooksConfig) { w.Enabled = false; w.Path = "" }, false},
		{"defaults valid", func(w *WebhooksConfig) { w.Enabled = true }, false},
		{"path must start with slash", func(w *WebhooksConfig) { w.Enabled = true; w.Path = "hooks" }, true},
		{"path cannot be root", func(w *WebhooksConfig) { w.Enabled = true; w.Path = "/" }, true},
		{"stream name cannot contain dots", func(w *WebhooksConfig) { w.Enabled = true; w.NATS.Stream = "a.b" }, true},
		{"prefix cannot contain wildcards", func(w *WebhooksConfig) { w.Enabled = true; w.NATS.SubjectPrefix = "gh.*" }, true},
		{"prefix cannot be empty", func(w *WebhooksConfig) { w.Enabled = true; w.NATS.SubjectPrefix = "" }, true},
		{"max payload must be positive", func(w *WebhooksConfig) { w.Enabled = true; w.MaxPayloadBytes = 0 }, true},
		{"max payload capped", func(w *WebhooksConfig) { w.Enabled = true; w.MaxPayloadBytes = MaxWebhookPayloadBytes + 1 }, true},
		{"listen requires auth token", func(w *WebhooksConfig) { w.Enabled = true; w.NATS.Listen = "127.0.0.1:4222" }, true},
		{"listen with auth token valid", func(w *WebhooksConfig) { w.Enabled = true; w.NATS.Listen = "127.0.0.1:4222"; w.NATS.AuthToken = "t" }, false},
		{"ngrok requires an authtoken", func(w *WebhooksConfig) { w.Enabled = true; w.Ngrok.Enabled = true }, true},
		{"ngrok with authtoken valid", func(w *WebhooksConfig) { w.Enabled = true; w.Ngrok.Enabled = true; w.Ngrok.Authtoken = "x" }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("NGROK_AUTHTOKEN", "")
			w := Defaults().Webhooks
			tt.mutate(&w)
			err := w.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWebhooksValidate_NgrokEnvToken(t *testing.T) {
	t.Setenv("NGROK_AUTHTOKEN", "from-env")
	w := Defaults().Webhooks
	w.Enabled = true
	w.Ngrok.Enabled = true
	if err := w.Validate(); err != nil {
		t.Errorf("expected NGROK_AUTHTOKEN to satisfy validation, got %v", err)
	}
	if w.NgrokAuthtoken() != "from-env" {
		t.Errorf("NgrokAuthtoken() = %q, want from-env", w.NgrokAuthtoken())
	}
}
