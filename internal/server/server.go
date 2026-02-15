package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"github.com/goodtune/ghp/internal/auth"
	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/proxy"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/goodtune/ghp/internal/token"
	"github.com/goodtune/ghp/internal/web"
)

// Server is the main ghp server.
type Server struct {
	cfg    *config.Config
	logger *slog.Logger
}

// New creates a new Server.
func New(cfg *config.Config, logger *slog.Logger) *Server {
	return &Server{cfg: cfg, logger: logger}
}

// Run starts the server and blocks until shutdown.
func (s *Server) Run(ctx context.Context) error {
	// Open database.
	store, err := database.Open(s.cfg.Database.Driver, s.cfg.Database.DSN)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer store.Close()

	// Check for pending migrations.
	migrator := database.NewMigrator(store, s.cfg.Database.Driver)
	pending, err := migrator.PendingMigrations(ctx)
	if err != nil {
		// If the migration table doesn't exist yet, that counts as pending.
		s.logger.Warn("could not check migrations", "error", err)
	} else if len(pending) > 0 {
		return fmt.Errorf("database has %d pending migration(s): run 'ghp migrate' first", len(pending))
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
	authHandler := auth.NewHandler(s.cfg, store, enc, s.logger)
	proxyHandler := proxy.NewHandler(s.cfg, tokenSvc, store, enc, s.logger)
	api := NewAPI(s.cfg, store, tokenSvc, authHandler, s.logger)
	webUI := web.NewHandler(authHandler, s.cfg.DevMode, s.logger)

	// Build HTTP mux.
	mux := http.NewServeMux()

	// Auth routes.
	authHandler.RegisterRoutes(mux)

	// API routes.
	api.RegisterRoutes(mux)

	// Web UI routes.
	webUI.RegisterRoutes(mux)

	// Metrics route (on management mux, not on GitHub-facing virtualhosts).
	if s.cfg.Metrics.Enabled {
		mux.Handle("/metrics", promhttp.Handler())
	}

	// Proxy routes — these catch /api/v3/* and /api/graphql.
	mux.Handle("/api/v3/", proxyHandler)
	mux.Handle("/api/graphql", proxyHandler)

	// Create passthrough handlers for github.com and *.githubcopilot.com.
	resolver := proxy.NewProxyTokenResolver(tokenSvc, store, enc)
	githubPassthrough := proxy.NewPassthroughHandler(
		"https://github.com", resolver, s.cfg.GitHub.EnterpriseSlug, s.logger, nil)
	copilotPassthrough := proxy.NewCopilotPassthroughHandler(
		"https://copilot-proxy.githubusercontent.com", s.cfg.GitHub.EnterpriseSlug, s.logger, nil)

	// Build host dispatch with access logging on GitHub-facing handlers.
	dispatch := newHostDispatch(hostDispatchConfig{
		apiHandler:     accessLogHandler(proxyHandler, s.logger),
		githubHandler:  accessLogHandler(githubPassthrough, s.logger),
		copilotHandler: accessLogHandler(copilotPassthrough, s.logger),
		mgmtHandler:    mux,
		managementHost: s.cfg.Server.ManagementHost,
	})

	// Platform-specific signal handling (e.g. SIGUSR1 on Unix).
	setupPlatformSignals(s.logger)

	// TLS mode: https_listen configured with certificates.
	if s.cfg.Server.HTTPSListen != "" {
		return s.serveTLS(ctx, dispatch)
	}

	// Legacy mode: plain HTTP on single port (no TLS).
	return s.servePlain(ctx, dispatch)
}

// serveTLS starts an HTTPS server with TLS termination and an optional
// HTTP redirect server. It blocks until shutdown.
func (s *Server) serveTLS(ctx context.Context, handler http.Handler) error {
	tlsCfg, err := loadTLSConfig(&s.cfg.TLS)
	if err != nil {
		return fmt.Errorf("loading TLS config: %w", err)
	}
	if tlsCfg == nil {
		return fmt.Errorf("https_listen configured but no TLS certificates provided")
	}

	httpsLn, err := net.Listen("tcp", s.cfg.Server.HTTPSListen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.cfg.Server.HTTPSListen, err)
	}
	tlsLn := tls.NewListener(httpsLn, tlsCfg)

	httpsServer := &http.Server{Handler: handler}

	// Start HTTP redirect server if configured.
	var httpServer *http.Server
	if s.cfg.Server.HTTPListen != "" {
		httpLn, err := net.Listen("tcp", s.cfg.Server.HTTPListen)
		if err != nil {
			return fmt.Errorf("listening on %s: %w", s.cfg.Server.HTTPListen, err)
		}
		httpServer = &http.Server{Handler: httpsRedirectHandler()}
		go httpServer.Serve(httpLn)
	}

	// Graceful shutdown for both servers.
	shutdownCtx, cancel := signal.NotifyContext(ctx, shutdownSignals()...)
	defer cancel()
	go func() {
		<-shutdownCtx.Done()
		s.logger.Info("server_shutdown", "msg", "shutting down")
		httpsServer.Shutdown(context.Background())
		if httpServer != nil {
			httpServer.Shutdown(context.Background())
		}
	}()

	s.logger.Info("server_ready",
		"https_listen", s.cfg.Server.HTTPSListen,
		"http_listen", s.cfg.Server.HTTPListen,
		"msg", "ready to accept connections")
	notifySystemd("READY=1")

	if err := httpsServer.Serve(tlsLn); err != http.ErrServerClosed {
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
		httpServer.Shutdown(context.Background())
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
		if fds := os.Getenv("LISTEN_FDS"); fds == "1" {
			f := os.NewFile(3, "systemd-socket")
			return net.FileListener(f)
		}
		s.logger.Warn("systemd socket activation configured but LISTEN_FDS not set, falling back to configured address")
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
		case host == "api.github.com":
			cfg.apiHandler.ServeHTTP(w, r)
		case host == "github.com":
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
