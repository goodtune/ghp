package server

import (
	"context"
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
	"github.com/goodtune/ghp/internal/metrics"
	"github.com/goodtune/ghp/internal/proxy"
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

	// Proxy routes — these catch /api/v3/* and /api/graphql.
	mux.Handle("/api/v3/", proxyHandler)
	mux.Handle("/api/graphql", proxyHandler)

	// Create listener.
	ln, err := s.createListener()
	if err != nil {
		return fmt.Errorf("creating listener: %w", err)
	}

	httpServer := &http.Server{
		Handler: hostRoutingHandler(mux, proxyHandler),
	}

	// Start metrics server if enabled.
	if s.cfg.Metrics.Enabled {
		go metrics.Serve(s.cfg.Metrics.Listen, s.logger)
	}

	// Graceful shutdown.
	shutdownCtx, cancel := signal.NotifyContext(ctx, shutdownSignals()...)
	defer cancel()

	go func() {
		<-shutdownCtx.Done()
		s.logger.Info("server_shutdown", "msg", "shutting down")
		httpServer.Shutdown(context.Background())
	}()

	// Platform-specific signal handling (e.g. SIGUSR1 on Unix).
	setupPlatformSignals(s.logger)

	s.logger.Info("server_ready", "listen", s.cfg.Server.Listen, "msg", "ready to accept connections")

	// Notify systemd if available.
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

// hostRoutingHandler routes requests based on the Host header.
// If the host is api.github.com (as when ghp is deployed as a virtualhost),
// all requests are sent directly to the proxy handler. Otherwise, the
// standard mux is used.
func hostRoutingHandler(mux *http.ServeMux, proxyHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == "api.github.com" {
			proxyHandler.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
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
