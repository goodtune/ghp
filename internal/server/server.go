package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/backend"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/docs"
	"github.com/goodtune/ghp/internal/github"
	"github.com/goodtune/ghp/internal/proxy"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/goodtune/ghp/internal/token"
	"github.com/goodtune/ghp/internal/web"
)

// Server is the main ghp server.
type Server struct {
	cfg        *config.Config
	configPath string
	logger     *slog.Logger
	logWriter  io.Writer
	store      database.Store
	migrate    bool
}

// New creates a new Server.
func New(cfg *config.Config, configPath string, logger *slog.Logger, logWriter io.Writer, migrate bool) *Server {
	if logWriter == nil {
		logWriter = io.Discard
	}
	return &Server{cfg: cfg, configPath: configPath, logger: logger, logWriter: logWriter, migrate: migrate}
}

// reloadConfig re-reads the configuration file and updates hot-reloadable
// fields in-place. All components holding a pointer to the Config struct
// will see the updated values.
func (s *Server) reloadConfig() {
	if s.configPath == "" {
		s.logger.Warn("config_reload_skipped", "msg", "no config file path, cannot reload")
		return
	}
	if err := s.cfg.ReloadFrom(s.configPath); err != nil {
		s.logger.Error("config_reload_failed", "error", err)
		return
	}
	s.logger.Info("config_reloaded", "path", s.configPath)

	// Sync admin roles from the updated config.
	if s.store != nil {
		if err := s.store.SyncAdminRoles(context.Background(), s.cfg.Admins); err != nil {
			s.logger.Error("admin_role_sync_failed", "error", err)
		} else {
			s.logger.Info("admin_roles_synced")
		}
	}
}

// Run starts the server and blocks until shutdown.
func (s *Server) Run(ctx context.Context) error {
	// Open database.
	store, err := database.Open(s.cfg.Database.Driver, s.cfg.Database.DSN)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer store.Close()
	s.store = store

	// Run or check migrations.
	migrator := database.NewMigrator(store, s.cfg.Database.Driver)
	if s.migrate {
		s.logger.Info("running database migrations before startup")
		if err := migrator.Migrate(ctx); err != nil {
			return fmt.Errorf("pre-startup migration: %w", err)
		}
		s.logger.Info("database migrations complete")
	} else {
		pending, err := migrator.PendingMigrations(ctx)
		if err != nil {
			s.logger.Warn("could not check migrations", "error", err)
		} else if len(pending) > 0 {
			return fmt.Errorf("database has %d pending migration(s): run 'ghp migrate' first", len(pending))
		}
	}

	// Sync admin roles from config on startup.
	if err := store.SyncAdminRoles(ctx, s.cfg.Admins); err != nil {
		s.logger.Warn("admin_role_sync_failed", "error", err)
	} else {
		s.logger.Info("admin_roles_synced")
	}

	// Set up encryption.
	encKey := s.cfg.EncryptionKey
	if encKey == "" {
		encKey = os.Getenv("GHP_ENCRYPTION_KEY")
	}
	if encKey == "" {
		return fmt.Errorf("encryption key not configured (set encryption_key in config or GHP_ENCRYPTION_KEY env var)")
	}
	enc, err := crypto.NewEncryptor(encKey)
	if err != nil {
		return fmt.Errorf("initializing encryption: %w", err)
	}

	// Create services.
	tokenSvc := token.NewService(store, s.cfg.Tokens.MaxDuration)

	// Optionally set up GitHub App token provider for agent (gha_) tokens.
	var appTokenProvider proxy.AppTokenProvider
	if s.cfg.GitHub.AppID != 0 {
		privateKey := s.cfg.GitHub.PrivateKey
		if privateKey == "" && s.cfg.GitHub.PrivateKeyFile != "" {
			keyData, err := os.ReadFile(s.cfg.GitHub.PrivateKeyFile)
			if err != nil {
				return fmt.Errorf("reading GitHub App private key file: %w", err)
			}
			privateKey = string(keyData)
		}
		if privateKey != "" {
			atp, err := github.NewAppTokenProvider(github.AppConfig{
				AppID:      s.cfg.GitHub.AppID,
				PrivateKey: privateKey,
			})
			if err != nil {
				return fmt.Errorf("initializing GitHub App token provider: %w", err)
			}
			appTokenProvider = atp
			s.logger.Info("github app token provider initialized", "app_id", s.cfg.GitHub.AppID)
		}
	}

	authHandler := auth.NewHandler(s.cfg, store, enc, s.logger)
	usernameResolver := proxy.NewUsernameResolver(store, s.logger)
	proxyHandler := proxy.NewHandler(s.cfg, tokenSvc, store, enc, appTokenProvider, usernameResolver, s.logger)

	// Recover the concrete *github.AppTokenProvider for admin API endpoints.
	var concreteATP *github.AppTokenProvider
	if atp, ok := appTokenProvider.(*github.AppTokenProvider); ok {
		concreteATP = atp
	}
	api := NewAPI(s.cfg, store, tokenSvc, authHandler, enc, concreteATP, s.logger)
	webUI := web.NewHandler(authHandler, s.cfg.DevMode, s.logger)

	// Build HTTP mux.
	mux := http.NewServeMux()

	// Auth routes.
	authHandler.RegisterRoutes(mux)

	// API routes.
	api.RegisterRoutes(mux)

	// Web UI routes.
	webUI.RegisterRoutes(mux)

	// Documentation site (embedded mkdocs output).
	mux.Handle("/docs/", http.StripPrefix("/docs/", docs.Handler()))
	mux.HandleFunc("GET /docs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
	})

	// Metrics route (on management mux, not on GitHub-facing virtualhosts).
	if s.cfg.Metrics.Enabled {
		mux.Handle("/metrics", promhttp.Handler())
	}

	// Proxy routes — these catch /api/v3/* and /api/graphql.
	mux.Handle("/api/v3/", proxyHandler)
	mux.Handle("/api/graphql", proxyHandler)

	// Create passthrough handlers for github.com and *.githubcopilot.com.
	resolver := proxy.NewProxyTokenResolver(tokenSvc, store, enc, appTokenProvider)
	githubInner := proxy.NewPassthroughHandler(
		"https://github.com", resolver, s.cfg.GitHub.EnterpriseSlug, s.logger, nil)
	githubPassthrough := proxy.NewScopedPassthroughHandler(
		githubInner, tokenSvc, resolver, usernameResolver, s.logger)
	copilotPassthrough := proxy.NewCopilotPassthroughHandler(
		"https://copilot-proxy.githubusercontent.com", s.cfg.GitHub.EnterpriseSlug, s.logger, nil)

	// Build access log writer for Caddy-compatible JSON access logs.
	aw := newAccessLogWriter(s.logWriter)

	// Build host dispatch with access logging on all handlers.
	dispatch := newHostDispatch(hostDispatchConfig{
		apiHandler:     accessLogHandler(backend.API, proxyHandler, aw),
		githubHandler:  accessLogHandler(backend.GitHub, githubPassthrough, aw),
		copilotHandler: accessLogHandler(backend.Copilot, copilotPassthrough, aw),
		mgmtHandler:    accessLogHandler(backend.Mgmt, web.SecurityHeadersMiddleware(mux), aw),
		managementHost: s.cfg.Server.ManagementHost,
	})

	// Platform-specific signal handling (e.g. SIGUSR1 on Unix for config reload).
	setupPlatformSignals(s.logger, s.reloadConfig)

	// TLS mode: https_listen configured, or socket activation with TLS certificates.
	hasTLS := s.cfg.Server.HTTPSListen != "" ||
		(s.cfg.Server.SystemdSocketActivation && len(s.cfg.TLS.Certificates) > 0)
	if hasTLS {
		return s.serveTLS(ctx, dispatch)
	}

	// Plain HTTP mode (single port, no TLS).
	return s.servePlain(ctx, dispatch)
}

// serveTLS starts an HTTPS server with TLS termination and an optional
// HTTP redirect server. It blocks until shutdown.
//
// With systemd socket activation, file descriptors are inherited from the
// socket unit. Two FDs means fd3=HTTP(80) and fd4=HTTPS(443); a single FD
// is used for HTTPS only.
func (s *Server) serveTLS(ctx context.Context, handler http.Handler) error {
	tlsCfg, err := loadTLSConfig(&s.cfg.TLS)
	if err != nil {
		return fmt.Errorf("loading TLS config: %w", err)
	}
	if tlsCfg == nil {
		return fmt.Errorf("TLS mode enabled but no certificates configured")
	}

	var httpsLn net.Listener
	var httpLn net.Listener // optional HTTP redirect listener

	if s.cfg.Server.SystemdSocketActivation {
		listeners, sdErr := systemdListeners()
		if sdErr != nil {
			s.logger.Warn("systemd_socket_fallback",
				"error", sdErr,
				"msg", "falling back to configured addresses")
		} else {
			switch len(listeners) {
			case 1:
				httpsLn = listeners[0]
			case 2:
				httpLn = listeners[0]  // fd 3 = port 80
				httpsLn = listeners[1] // fd 4 = port 443
			default:
				for _, ln := range listeners {
					ln.Close()
				}
				return fmt.Errorf("expected 1-2 systemd sockets for TLS mode, got %d", len(listeners))
			}
		}
	}

	// Fall back to configured addresses when systemd sockets are unavailable.
	if httpsLn == nil {
		if s.cfg.Server.HTTPSListen == "" {
			return fmt.Errorf("https_listen not configured and no systemd socket available")
		}
		httpsLn, err = net.Listen("tcp", s.cfg.Server.HTTPSListen)
		if err != nil {
			return fmt.Errorf("listening on %s: %w", s.cfg.Server.HTTPSListen, err)
		}
	}

	tlsLn := tls.NewListener(httpsLn, tlsCfg)

	// Set TLSConfig so HTTP/2 is auto-configured by net/http.
	httpsServer := &http.Server{Handler: handler, TLSConfig: tlsCfg}

	// Start HTTP redirect server from systemd socket or configured address.
	var httpServer *http.Server
	if httpLn != nil {
		httpServer = &http.Server{Handler: httpsRedirectHandler()}
		go func() {
			if err := httpServer.Serve(httpLn); err != nil && err != http.ErrServerClosed {
				s.logger.Error("http_redirect_server_error", "err", err)
			}
		}()
	} else if s.cfg.Server.HTTPListen != "" {
		cfgLn, err := net.Listen("tcp", s.cfg.Server.HTTPListen)
		if err != nil {
			tlsLn.Close()
			return fmt.Errorf("listening on %s: %w", s.cfg.Server.HTTPListen, err)
		}
		httpServer = &http.Server{Handler: httpsRedirectHandler()}
		go func() {
			if err := httpServer.Serve(cfgLn); err != nil && err != http.ErrServerClosed {
				s.logger.Error("http_redirect_server_error",
					"listen_addr", s.cfg.Server.HTTPListen,
					"err", err)
			}
		}()
	}

	// Graceful shutdown for both servers.
	shutdownCtx, cancel := signal.NotifyContext(ctx, shutdownSignals()...)
	defer cancel()
	go func() {
		<-shutdownCtx.Done()
		s.logger.Info("server_shutdown", "msg", "shutting down")
		timeout, tcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer tcancel()
		httpsServer.Shutdown(timeout)
		if httpServer != nil {
			httpServer.Shutdown(timeout)
		}
	}()

	s.logger.Info("server_ready",
		"mode", "tls",
		"systemd", s.cfg.Server.SystemdSocketActivation,
		"msg", "ready to accept connections")
	notifySystemd("READY=1")

	if err := httpsServer.Serve(tlsLn); err != http.ErrServerClosed {
		if httpServer != nil {
			httpServer.Close()
		}
		return fmt.Errorf("server error: %w", err)
	}
	notifySystemd("STOPPING=1")
	return nil
}

// servePlain starts a plain HTTP server (legacy mode, no TLS). It blocks
// until shutdown.
func (s *Server) servePlain(ctx context.Context, handler http.Handler) error {
	ln, err := s.createListener()
	if err != nil {
		return fmt.Errorf("creating listener: %w", err)
	}

	httpServer := &http.Server{Handler: handler}

	shutdownCtx, cancel := signal.NotifyContext(ctx, shutdownSignals()...)
	defer cancel()
	go func() {
		<-shutdownCtx.Done()
		s.logger.Info("server_shutdown", "msg", "shutting down")
		timeout, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		httpServer.Shutdown(timeout)
	}()

	s.logger.Info("server_ready", "listen", s.cfg.Server.Listen, "msg", "ready to accept connections")
	notifySystemd("READY=1")

	if err := httpServer.Serve(ln); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	notifySystemd("STOPPING=1")
	return nil
}

func (s *Server) createListener() (net.Listener, error) {
	addr := s.cfg.Server.Listen

	// Check for systemd socket activation.
	if s.cfg.Server.SystemdSocketActivation {
		listeners, err := systemdListeners()
		if err != nil {
			s.logger.Warn("systemd_socket_fallback",
				"error", err,
				"msg", "falling back to configured address")
		} else if len(listeners) >= 1 {
			// Use the first listener; close any extras (plain mode needs one).
			for _, ln := range listeners[1:] {
				ln.Close()
			}
			return listeners[0], nil
		}
	}

	// Unix socket.
	if strings.HasPrefix(addr, "unix://") {
		sockPath := strings.TrimPrefix(addr, "unix://")
		os.Remove(sockPath) // Clean up stale socket.
		return net.Listen("unix", sockPath)
	}

	// TCP.
	return net.Listen("tcp", addr)
}

// systemdListeners returns net.Listeners for each file descriptor passed
// by the systemd socket activation protocol (LISTEN_FDS).
func systemdListeners() ([]net.Listener, error) {
	fdsStr := os.Getenv("LISTEN_FDS")
	if fdsStr == "" {
		return nil, fmt.Errorf("LISTEN_FDS not set")
	}
	nfds, err := strconv.Atoi(fdsStr)
	if err != nil || nfds <= 0 {
		return nil, fmt.Errorf("invalid LISTEN_FDS value: %s", fdsStr)
	}
	listeners := make([]net.Listener, 0, nfds)
	for i := 0; i < nfds; i++ {
		fd := 3 + i
		f := os.NewFile(uintptr(fd), fmt.Sprintf("systemd-socket-%d", i))
		ln, err := net.FileListener(f)
		f.Close()
		if err != nil {
			for _, prev := range listeners {
				prev.Close()
			}
			return nil, fmt.Errorf("creating listener from fd %d: %w", fd, err)
		}
		listeners = append(listeners, ln)
	}
	return listeners, nil
}

type hostDispatchConfig struct {
	apiHandler     http.Handler
	githubHandler  http.Handler
	copilotHandler http.Handler
	mgmtHandler    http.Handler
	managementHost string
}

// newHostDispatch creates a handler that routes requests by Host header.
func newHostDispatch(cfg hostDispatchConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		switch {
		case host == backend.API:
			cfg.apiHandler.ServeHTTP(w, r)
		case host == backend.GitHub:
			cfg.githubHandler.ServeHTTP(w, r)
		case host == "githubcopilot.com" || strings.HasSuffix(host, ".githubcopilot.com"):
			cfg.copilotHandler.ServeHTTP(w, r)
		case cfg.managementHost == "" || strings.EqualFold(host, cfg.managementHost):
			cfg.mgmtHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func notifySystemd(state string) {
	socketPath := os.Getenv("NOTIFY_SOCKET")
	if socketPath == "" {
		return
	}
	conn, err := net.Dial("unixgram", socketPath)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write([]byte(state))
}
