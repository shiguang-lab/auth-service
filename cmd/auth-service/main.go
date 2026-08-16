package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/shiguanglab/auth-service/internal/authorize"
	"github.com/shiguanglab/auth-service/internal/config"
	"github.com/shiguanglab/auth-service/internal/httpapi"
	"github.com/shiguanglab/auth-service/internal/identity"
	loginservice "github.com/shiguanglab/auth-service/internal/login"
	orgservice "github.com/shiguanglab/auth-service/internal/orgs"
	"github.com/shiguanglab/auth-service/internal/session"
	"github.com/shiguanglab/auth-service/internal/zitadel"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	signer, err := identity.NewSigner(cfg.IdentityIssuer, cfg.SigningKeyID, cfg.SigningKeyFile, cfg.IdentityTokenTTL)
	if err != nil {
		logger.Error("initialize identity signer", "error", err)
		os.Exit(1)
	}
	redisOptions, err := redisConfig(cfg)
	if err != nil {
		logger.Error("initialize redis configuration", "error", err)
		os.Exit(1)
	}
	store, err := newSessionStore(cfg, redisOptions)
	if err != nil {
		logger.Error("initialize session store", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Error("close session store", "error", err)
		}
	}()
	startupContext, cancelStartup := context.WithTimeout(context.Background(), 20*time.Second)
	login, err := loginservice.NewService(startupContext, cfg, store, redisOptions, logger)
	cancelStartup()
	if err != nil {
		logger.Error("initialize login service", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := login.Close(); err != nil {
			logger.Error("close login service", "error", err)
		}
	}()

	decision := authorize.NewService(store, signer, cfg.SessionCookieName, cfg.IdleTTL, cfg.AbsoluteTTL)
	readiness := func(ctx context.Context) error {
		if err := store.Ping(ctx); err != nil {
			return err
		}
		return login.Ping(ctx)
	}
	api := httpapi.NewServer(decision, signer, cfg.GatewayToken, readiness, logger, login)
	if cfg.LocalBrokerEnabled {
		api.WithLocalBroker(httpapi.LocalBrokerPolicy{
			PublicOrigin:         cfg.PublicOrigin,
			ProductID:            cfg.LocalBrokerProductID,
			Audience:             cfg.LocalBrokerAudience,
			RequiredEntitlements: cfg.LocalBrokerEntitlements,
			BrokerTTL:            cfg.LocalBrokerTTL,
			IdentityTTL:          cfg.IdentityTokenTTL,
		})
	}
	if login != nil && cfg.ZitadelProjectID != "" {
		directory, err := zitadel.NewClient(
			cfg.ZitadelInternalURL,
			cfg.ZitadelIssuer,
			cfg.ZitadelPATFile,
			cfg.ZitadelRegistrationPATFile,
			cfg.ZitadelOrganizationID,
		)
		if err != nil {
			logger.Error("initialize organization directory client", "error", err)
			os.Exit(1)
		}
		api.WithOrganizations(orgservice.NewService(cfg, store, login, directory, logger))
	}
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	go func() {
		logger.Info("auth service listening",
			"addr", cfg.Addr,
			"environment", cfg.Environment,
			"session_backend", cfg.SessionBackend,
		)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	}()

	stop, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	<-stop.Done()

	ctx, shutdown := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdown()
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
}

func newSessionStore(cfg config.Config, options *redis.Options) (session.Store, error) {
	switch cfg.SessionBackend {
	case "memory":
		return session.NewMemoryStore(), nil
	case "redis":
		return session.NewRedisStore(options, cfg.RedisKeyPrefix, cfg.AbsoluteTTL, cfg.SessionEncryptionKey)
	default:
		return nil, fmt.Errorf("unsupported session backend %q", cfg.SessionBackend)
	}
}

func redisConfig(cfg config.Config) (*redis.Options, error) {
	if cfg.SessionBackend != "redis" {
		return nil, nil
	}
	options, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("parse REDIS_URL: %w", err)
	}
	return options, nil
}
