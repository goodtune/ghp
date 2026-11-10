package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	osexec "os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/goodtune/ghp/tools/scoperig/redact"
	"github.com/goodtune/ghp/tools/scoperig/scenario"
)

// Config is the rig's resolved configuration. Environment variables override
// rig/config.yaml. GHP_SERVER_URL and GHP_USER_TOKEN use the same names as
// the ghp CLI; they are only required for paths that talk to the instance
// (see RequireServer), so validate-only runs work with no environment.
type Config struct {
	ServerURL, UserToken string // GHP_SERVER_URL, GHP_USER_TOKEN
	RepoA, RepoB, RepoW  string // env > rig/config.yaml fixtures
	GHPath, Root, CAFile string // GHP_RIG_GH, GHP_RIG_SCENARIOS (default "rig"), GHP_RIG_CA_FILE
	// InstallationID is instance.agent_installation.installation_id,
	// overridden by GHP_RIG_INSTALLATION_ID.
	InstallationID int64
	// AgentAppRecordID is instance.agent_installation.app_record_id: the
	// GHP app record agent profiles are minted against.
	AgentAppRecordID string
	Instance         scenario.InstanceVals
	TokenCreateRate  int // per minute, from "20/min"
	// BorderBlock is the operator-declared list of token prefixes the
	// instance's border policy blocks (instance.border_block). The rig does
	// not probe it; ProbeCapabilities turns it into border_block_* capabilities.
	BorderBlock []string
	// AllowNoExpiry is the operator-declared instance tokens.allow_no_expiry
	// (instance.allow_no_expiry); nil when not declared. The instance does
	// not expose it, so it is never probed.
	AllowNoExpiry *bool
	// GHPPath is the ghp CLI binary for git_credential scenarios
	// (GHP_RIG_GHP, else ghp on PATH).
	GHPPath string
	// Metrics configures the optional advisory latency section.
	Metrics                                       MetricsConfig
	ConfigFile, Out, Only                         string
	SkipKnown, KeepGoing, Verbose, CreateFixtures bool
}

// MetricsConfig is the optional metrics block. An empty PrometheusURL skips
// the latency section ("not configured").
type MetricsConfig struct {
	// PrometheusURL is a Prometheus base URL or a Grafana datasource proxy
	// URL (<grafana>/api/datasources/proxy/uid/<uid>); /api/v1/query is
	// appended.
	PrometheusURL string
	// BearerTokenEnv names an environment variable holding a bearer token
	// for PrometheusURL; empty means anonymous.
	BearerTokenEnv string
	// Bearer is the token read from BearerTokenEnv.
	Bearer string
	// Selector is extra label matchers for every series, e.g. job="ghp".
	Selector string
	// ScrapeWait is how long the rig waits after the last scenario so that
	// Prometheus scrapes the run's final observations. Default 45s.
	ScrapeWait time.Duration
}

// defaultScrapeWait is metrics.scrape_wait when omitted: one 30s scrape
// interval plus margin.
const defaultScrapeWait = 45 * time.Second

type fileConfig struct {
	Instance struct {
		Host            string   `yaml:"host"`
		DefaultDuration string   `yaml:"default_duration"`
		MaxDuration     string   `yaml:"max_duration"`
		TokenCreateRate string   `yaml:"token_create_rate"`
		BorderBlock     []string `yaml:"border_block"`
		AllowNoExpiry   *bool    `yaml:"allow_no_expiry"`
		// AgentInstallation is the GitHub App installation agent (gha_)
		// profiles mint against (issue #306).
		AgentInstallation struct {
			AppRecordID    string `yaml:"app_record_id"`
			InstallationID *int64 `yaml:"installation_id"`
		} `yaml:"agent_installation"`
	} `yaml:"instance"`
	Metrics struct {
		PrometheusURL  string `yaml:"prometheus_url"`
		BearerTokenEnv string `yaml:"bearer_token_env"`
		Selector       string `yaml:"selector"`
		ScrapeWait     string `yaml:"scrape_wait"`
	} `yaml:"metrics"`
	Fixtures struct {
		RepoA string `yaml:"repo_a"`
		RepoB string `yaml:"repo_b"`
		RepoW string `yaml:"repo_w"`
	} `yaml:"fixtures"`
}

// lookPath finds gh on PATH when GHP_RIG_GH is unset (a var for tests).
var lookPath = osexec.LookPath

// LoadConfig reads configFile and applies environment overrides. It does not
// require GHP_SERVER_URL or GHP_USER_TOKEN; call RequireServer before any
// network use.
func LoadConfig(getenv func(string) string, configFile string) (*Config, error) {
	raw, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var fc fileConfig
	if err := yaml.Unmarshal(raw, &fc); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", configFile, err)
	}
	c := &Config{
		ServerURL:     strings.TrimRight(strings.TrimSpace(getenv("GHP_SERVER_URL")), "/"),
		UserToken:     strings.TrimSpace(getenv("GHP_USER_TOKEN")),
		RepoA:         firstNonEmpty(getenv("GHP_RIG_REPO_A"), fc.Fixtures.RepoA),
		RepoB:         firstNonEmpty(getenv("GHP_RIG_REPO_B"), fc.Fixtures.RepoB),
		RepoW:         firstNonEmpty(getenv("GHP_RIG_REPO_W"), fc.Fixtures.RepoW),
		GHPath:        getenv("GHP_RIG_GH"),
		Root:          firstNonEmpty(getenv("GHP_RIG_SCENARIOS"), "rig"),
		CAFile:        getenv("GHP_RIG_CA_FILE"),
		ConfigFile:    configFile,
		BorderBlock:   fc.Instance.BorderBlock,
		AllowNoExpiry: fc.Instance.AllowNoExpiry,
		GHPPath:       getenv("GHP_RIG_GHP"),
		Instance: scenario.InstanceVals{
			Host: strings.TrimSpace(fc.Instance.Host),
		},
	}
	if c.GHPath == "" {
		if p, err := lookPath("gh"); err == nil {
			c.GHPath = p
		}
	}
	if c.GHPPath == "" {
		if p, err := lookPath("ghp"); err == nil {
			c.GHPPath = p
		}
	}
	if c.ServerURL != "" {
		u, err := url.Parse(c.ServerURL)
		// https only: the session token travels on management calls, and
		// gh always speaks https to the proxy host.
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("GHP_SERVER_URL must be an https URL")
		}
		// A host left empty in the file is derived from GHP_SERVER_URL.
		// Management calls always use GHP_SERVER_URL itself.
		if c.Instance.Host == "" {
			c.Instance.Host = u.Host
		}
	}
	ai := fc.Instance.AgentInstallation
	c.AgentAppRecordID = strings.TrimSpace(ai.AppRecordID)
	if c.AgentAppRecordID != "" && !uuidRE.MatchString(c.AgentAppRecordID) {
		return nil, errors.New("instance.agent_installation.app_record_id must be a UUID (the app's record id from GET /api/apps)")
	}
	if ai.InstallationID != nil {
		if *ai.InstallationID <= 0 {
			return nil, errors.New("instance.agent_installation.installation_id must be a positive integer")
		}
		c.InstallationID = *ai.InstallationID
	}
	if s := getenv("GHP_RIG_INSTALLATION_ID"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("GHP_RIG_INSTALLATION_ID must be a positive integer")
		}
		c.InstallationID = n
	}
	if c.Instance.DefaultDuration, err = optDuration("instance.default_duration", fc.Instance.DefaultDuration); err != nil {
		return nil, err
	}
	if c.Instance.MaxDuration, err = optDuration("instance.max_duration", fc.Instance.MaxDuration); err != nil {
		return nil, err
	}
	c.TokenCreateRate = defaultTokenCreateRate
	if fc.Instance.TokenCreateRate != "" {
		if c.TokenCreateRate, err = parseRate(fc.Instance.TokenCreateRate); err != nil {
			return nil, fmt.Errorf("instance.token_create_rate: %w", err)
		}
	}
	if c.Metrics, err = loadMetrics(getenv, fc, c.UserToken); err != nil {
		return nil, err
	}
	return c, nil
}

// maxScrapeWait caps metrics.scrape_wait so that a typo cannot hang the rig.
const maxScrapeWait = 5 * time.Minute

// selectorMatcher matches one PromQL label matcher, label op "value", at the
// start of the input, with an optional trailing comma.
var selectorMatcher = regexp.MustCompile(`^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*(=~|!~|!=|=)\s*"(?:[^"\\]|\\.)*"\s*(,|$)`)

// validateSelector accepts only a comma-separated list of label matchers.
func validateSelector(sel string) error {
	rest := sel
	for rest != "" {
		loc := selectorMatcher.FindStringIndex(rest)
		if loc == nil {
			bad := rest
			if i := strings.IndexByte(bad, ','); i >= 0 {
				bad = bad[:i]
			}
			return fmt.Errorf("metrics.selector: bad matcher %q: want label op \"value\" with op one of = != =~ !~", strings.TrimSpace(bad))
		}
		consumed := rest[:loc[1]]
		rest = rest[loc[1]:]
		if strings.HasSuffix(consumed, ",") && strings.TrimSpace(rest) == "" {
			return errors.New(`metrics.selector: bad matcher "": trailing comma`)
		}
	}
	return nil
}

func loadMetrics(getenv func(string) string, fc fileConfig, userToken string) (MetricsConfig, error) {
	fm := fc.Metrics
	m := MetricsConfig{
		PrometheusURL:  strings.TrimSpace(fm.PrometheusURL),
		BearerTokenEnv: strings.TrimSpace(fm.BearerTokenEnv),
		Selector:       strings.TrimSpace(fm.Selector),
		ScrapeWait:     defaultScrapeWait,
	}
	if m.PrometheusURL != "" {
		u, err := url.Parse(m.PrometheusURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return m, errors.New("metrics.prometheus_url must be an http(s) URL without credentials, query or fragment")
		}
	}
	if strings.ContainsAny(m.Selector, "{}") {
		return m, errors.New("metrics.selector: give label matchers only, without braces (for example job=\"ghp\")")
	}
	if m.Selector != "" {
		if err := validateSelector(m.Selector); err != nil {
			return m, err
		}
	}
	if m.BearerTokenEnv != "" {
		m.Bearer = strings.TrimSpace(getenv(m.BearerTokenEnv))
		if m.Bearer == "" && m.PrometheusURL != "" {
			return m, fmt.Errorf("metrics.bearer_token_env: %s is not set", m.BearerTokenEnv)
		}
		if m.Bearer != "" {
			if userToken != "" && m.Bearer == userToken {
				return m, fmt.Errorf("metrics.bearer_token_env: %s holds the GHP user token; give a separate Prometheus token", m.BearerTokenEnv)
			}
			if redact.Pattern.MatchString(m.Bearer) {
				return m, fmt.Errorf("metrics.bearer_token_env: %s looks like a GitHub or GHP token; give a separate Prometheus token", m.BearerTokenEnv)
			}
			if m.PrometheusURL != "" && !strings.HasPrefix(m.PrometheusURL, "https://") {
				return m, errors.New("metrics.prometheus_url must use https when metrics.bearer_token_env is set")
			}
		}
	}
	if fm.ScrapeWait != "" {
		d, err := time.ParseDuration(fm.ScrapeWait)
		if err != nil || d < 0 {
			return m, fmt.Errorf("metrics.scrape_wait: want a non-negative duration such as 45s")
		}
		if d > maxScrapeWait {
			return m, fmt.Errorf("metrics.scrape_wait: %s is too long; give at most 5m", d)
		}
		m.ScrapeWait = d
	}
	return m, nil
}

// uuidRE matches the canonical 8-4-4-4-12 hex form only (no braces or urn:
// prefix), the form GHP's API accepts for app_record_id.
var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// AgentConfigured reports whether both agent installation values are set.
// The agent_installation capability also needs the app to exist.
func (c *Config) AgentConfigured() bool {
	return c.AgentAppRecordID != "" && c.InstallationID > 0
}

// RequireServer reports, by name, which instance credentials are missing.
func (c *Config) RequireServer() error {
	var missing []string
	if c.ServerURL == "" {
		missing = append(missing, "GHP_SERVER_URL")
	}
	if c.UserToken == "" {
		missing = append(missing, "GHP_USER_TOKEN")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s not set (same variables as the ghp CLI)", strings.Join(missing, " and "))
	}
	return nil
}

// placeholderOwner is the fixture owner in rig/config.example.yaml.
const placeholderOwner = "OWNER"

// RequireFixtureOwners rejects fixture repositories still owned by the
// example config's placeholder owner.
func (c *Config) RequireFixtureOwners() error {
	for _, kv := range [][2]string{{"repo_a", c.RepoA}, {"repo_b", c.RepoB}, {"repo_w", c.RepoW}} {
		if owner, _, _ := strings.Cut(kv[1], "/"); owner == placeholderOwner {
			return fmt.Errorf("fixtures.%s owner is the placeholder %s: copy rig/config.example.yaml to rig/config.yaml and set the fixture owner (or set GHP_RIG_REPO_A/B/W)", kv[0], placeholderOwner)
		}
	}
	return nil
}

// HTTPClient returns a client trusting the system pool plus CAFile.
func (c *Config) HTTPClient() (*http.Client, error) {
	pool, err := c.rootPool()
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = newTLSConfig(pool)
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}

func (c *Config) rootPool() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("GHP_RIG_CA_FILE: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("GHP_RIG_CA_FILE: no PEM certificates found")
		}
	}
	return pool, nil
}

// String describes the config without the user token.
func (c *Config) String() string {
	tok := "unset"
	if c.UserToken != "" {
		tok = "[REDACTED]"
	}
	return fmt.Sprintf("Config{server=%s token=%s host=%s repos=%s,%s,%s root=%s gh=%s ca=%s app=%s installation=%d rate=%d/min}",
		c.ServerURL, tok, c.Instance.Host, c.RepoA, c.RepoB, c.RepoW,
		c.Root, c.GHPath, c.CAFile, c.AgentAppRecordID, c.InstallationID, c.TokenCreateRate)
}

// GoString keeps %#v from dumping the struct fields (and the token).
func (c *Config) GoString() string { return c.String() }

// Format routes every verb (including %+v) through String.
func (c *Config) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(c.String())) }

// defaultTokenCreateRate is the token create rate (per minute) used when
// instance.token_create_rate is omitted.
const defaultTokenCreateRate = 20

// parseRate parses "N/min" (also "N/m", "N/minute") into N per minute.
func parseRate(s string) (int, error) {
	n, unit, ok := strings.Cut(s, "/")
	if !ok {
		return 0, fmt.Errorf("rate %q: want N/min", s)
	}
	switch strings.TrimSpace(unit) {
	case "min", "m", "minute":
	default:
		return 0, fmt.Errorf("rate %q: unit must be /min", s)
	}
	v, err := strconv.Atoi(strings.TrimSpace(n))
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("rate %q: count must be a positive integer", s)
	}
	return v, nil
}

func optDuration(name, s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return d, nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
