package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	osexec "os/exec"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

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
	InstallationID       int64  // GHP_RIG_INSTALLATION_ID
	Instance             scenario.InstanceVals
	TokenCreateRate      int // per minute, from "20/min"
	// BorderBlock is the operator-declared list of token prefixes the
	// instance's border policy blocks (instance.border_block). The rig does
	// not probe it; ProbeCapabilities turns it into border_block_* capabilities.
	BorderBlock                                   []string
	ConfigFile, Out, Only                         string
	SkipKnown, KeepGoing, Verbose, CreateFixtures bool
}

type fileConfig struct {
	Instance struct {
		Host            string   `yaml:"host"`
		DefaultDuration string   `yaml:"default_duration"`
		MaxDuration     string   `yaml:"max_duration"`
		TokenCreateRate string   `yaml:"token_create_rate"`
		BorderBlock     []string `yaml:"border_block"`
	} `yaml:"instance"`
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
		ServerURL:   strings.TrimRight(strings.TrimSpace(getenv("GHP_SERVER_URL")), "/"),
		UserToken:   strings.TrimSpace(getenv("GHP_USER_TOKEN")),
		RepoA:       firstNonEmpty(getenv("GHP_RIG_REPO_A"), fc.Fixtures.RepoA),
		RepoB:       firstNonEmpty(getenv("GHP_RIG_REPO_B"), fc.Fixtures.RepoB),
		RepoW:       firstNonEmpty(getenv("GHP_RIG_REPO_W"), fc.Fixtures.RepoW),
		GHPath:      getenv("GHP_RIG_GH"),
		Root:        firstNonEmpty(getenv("GHP_RIG_SCENARIOS"), "rig"),
		CAFile:      getenv("GHP_RIG_CA_FILE"),
		ConfigFile:  configFile,
		BorderBlock: fc.Instance.BorderBlock,
		Instance: scenario.InstanceVals{
			Host: strings.TrimSpace(fc.Instance.Host),
		},
	}
	if c.GHPath == "" {
		if p, err := lookPath("gh"); err == nil {
			c.GHPath = p
		}
	}
	if c.ServerURL != "" {
		u, err := url.Parse(c.ServerURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, fmt.Errorf("GHP_SERVER_URL must be an http(s) URL")
		}
		// A host left empty in the file is derived from GHP_SERVER_URL.
		// Management calls always use GHP_SERVER_URL itself.
		if c.Instance.Host == "" {
			c.Instance.Host = u.Host
		}
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
	return c, nil
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
	return fmt.Sprintf("Config{server=%s token=%s host=%s repos=%s,%s,%s root=%s gh=%s ca=%s installation=%d rate=%d/min}",
		c.ServerURL, tok, c.Instance.Host, c.RepoA, c.RepoB, c.RepoW,
		c.Root, c.GHPath, c.CAFile, c.InstallationID, c.TokenCreateRate)
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
