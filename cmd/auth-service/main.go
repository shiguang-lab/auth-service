package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shiguanglab/auth-service/internal/authorize"
	"github.com/shiguanglab/auth-service/internal/config"
	"github.com/shiguanglab/auth-service/internal/httpapi"
	"github.com/shiguanglab/auth-service/internal/identity"
	"github.com/shiguanglab/auth-service/internal/session"
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

	store := session.NewMemoryStore()
	decision := authorize.NewService(store, signer, cfg.SessionCookieName, cfg.IdleTTL, cfg.AbsoluteTTL)
	api := httpapi.NewServer(decision, signer, cfg.GatewayToken, logger)
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	go func() {
		logger.Info("auth service listening", "addr", cfg.Addr, "environment", cfg.Environment)
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
