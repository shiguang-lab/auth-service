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
	"github.com/shiguanglab/auth-service/internal/localidentity"
	loginservice "github.com/shiguanglab/auth-service/internal/login"
	oauthservice "github.com/shiguanglab/auth-service/internal/oauth"
	orgservice "github.com/shiguanglab/auth-service/internal/orgs"
	"github.com/shiguanglab/auth-service/internal/platformroleadmin"
	"github.com/shiguanglab/auth-service/internal/platformroles"
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
	var roleCommandJournal *platformroleadmin.RedisCommandJournal
	if cfg.SessionBackend == "redis" {
		roleCommandJournal, err = platformroleadmin.NewRedisCommandJournal(redisOptions, cfg.IAMRoleCommandPrefix, cfg.SessionEncryptionKey)
		if err != nil {
			logger.Error("initialize IAM role command journal", "error", err)
			os.Exit(1)
		}
		defer func() {
			if err := roleCommandJournal.Close(); err != nil {
				logger.Error("close IAM role command journal", "error", err)
			}
		}()
	}
	startupContext, cancelStartup := context.WithTimeout(context.Background(), 20*time.Second)
	login, err := loginservice.NewService(startupContext, cfg, store, redisOptions, logger)
	cancelStartup()
	if err != nil {
		logger.Error("initialize login service", "error", err)
		os.Exit(1)
	}
	defer func() {
		if login != nil {
			if err := login.Close(); err != nil {
				logger.Error("close login service", "error", err)
			}
		}
	}()

	var localFixture *localidentity.Service
	var localExecutor *platformroleadmin.DurableChangeExecutor
	if cfg.LocalIdentityFixture {
		localFixture, err = localidentity.New(localidentity.Config{
			Origin:         cfg.LocalIdentityOrigin,
			CookieName:     cfg.SessionCookieName,
			CookieTTL:      cfg.AbsoluteTTL,
			IdentityIssuer: cfg.IdentityIssuer,
			IdentityToken:  cfg.LocalIdentityServiceToken,
			RedisPrefix:    cfg.LocalIdentityRedisPrefix,
		}, store, redisOptions, logger)
		if err != nil {
			logger.Error("initialize local identity fixture", "error", err)
			os.Exit(1)
		}
		defer func() {
			if err := localFixture.Close(); err != nil {
				logger.Error("close local identity fixture", "error", err)
			}
		}()
		if roleCommandJournal == nil {
			logger.Error("local identity fixture requires IAM command journal")
			os.Exit(1)
		}
		localExecutor, err = platformroleadmin.NewDurableChangeExecutor(roleCommandJournal, localFixture, cfg.IAMRoleCommandTTL, 10*time.Second)
		if err != nil {
			logger.Error("initialize local IAM role executor", "error", err)
			os.Exit(1)
		}
		localFixture.SetExecutor(localExecutor)
		seedContext, cancelSeed := context.WithTimeout(context.Background(), 5*time.Second)
		err = localFixture.Seed(seedContext)
		cancelSeed()
		if err != nil {
			logger.Error("seed local identity fixture", "error", err)
			os.Exit(1)
		}
	}

	decision := authorize.NewService(store, signer, cfg.SessionCookieName, cfg.IdleTTL, cfg.AbsoluteTTL)
	if localFixture != nil {
		decision.WithPlatformRoleRefresher(localFixture)
	}
	var directory *zitadel.Client
	var roleDirectory platformroleadmin.Directory
	if login != nil && cfg.ZitadelProjectID != "" {
		directory, err = zitadel.NewClient(
			cfg.ZitadelInternalURL,
			cfg.ZitadelIssuer,
			cfg.ZitadelPATFile,
			cfg.ZitadelRegistrationPATFile,
			cfg.ZitadelOrganizationID,
		)
		if err != nil {
			logger.Error("initialize platform directory client", "error", err)
			os.Exit(1)
		}
		roleDirectory = platformroleadmin.NewZitadelDirectory(directory, cfg.ZitadelOrganizationID, cfg.ZitadelProjectID)
		roleRefresher := platformroles.New(store, directory, cfg.ZitadelOrganizationID, cfg.ZitadelProjectID, logger)
		login.WithPlatformRoleRefresher(roleRefresher)
		decision.WithPlatformRoleRefresher(roleRefresher)
	}
	readiness := func(ctx context.Context) error {
		if err := store.Ping(ctx); err != nil {
			return err
		}
		if login != nil {
			if err := login.Ping(ctx); err != nil {
				return err
			}
		}
		if localFixture != nil {
			if err := localFixture.Ping(ctx); err != nil {
				return err
			}
		}
		if roleCommandJournal != nil {
			return roleCommandJournal.Ping(ctx)
		}
		return nil
	}
	api := httpapi.NewServer(decision, signer, cfg.GatewayToken, readiness, logger, login)
	if cfg.LocalBrokerEnabled {
		for _, policy := range cfg.EffectiveLocalBrokerPolicies() {
			api.WithLocalBroker(httpapi.LocalBrokerPolicy{
				PublicOrigin:         cfg.PublicOrigin,
				ProductID:            policy.ProductID,
				Audience:             policy.Audience,
				RequiredEntitlements: policy.RequiredEntitlements,
				BrokerTTL:            cfg.LocalBrokerTTL,
				IdentityTTL:          cfg.IdentityTokenTTL,
			})
		}
	}
	if localFixture != nil {
		api.WithLocalIdentity(localFixture)
		api.WithPlatformRoleAdmin(platformroleadmin.NewService(localFixture, localFixture, localExecutor, localFixture, cfg.IAMRoleAdminOrigins, logger))
		api.WithProductRoleAdmin(platformroleadmin.NewProductService(localFixture, localFixture, localExecutor, localFixture, cfg.IAMRoleAdminOrigins, logger))
	} else if login != nil {
		// The Redis command journal is ready when configured, but the executor
		// remains nil until a ZITADEL writer and permanent audit sink are approved.
		api.WithPlatformRoleAdmin(platformroleadmin.NewService(login, roleDirectory, nil, nil, cfg.IAMRoleAdminOrigins, logger))
		api.WithProductRoleAdmin(platformroleadmin.NewProductService(login, roleDirectory, nil, nil, cfg.IAMRoleAdminOrigins, logger))
	}
	if directory != nil {
		api.WithOrganizations(orgservice.NewService(cfg, store, login, directory, logger))
	}
	if cfg.OAuthEnabled {
		registry, err := oauthservice.NewRegistry([]oauthservice.ClientPolicy{{
			ClientID:     cfg.OAuthClientID,
			Name:         cfg.OAuthClientName,
			RedirectURIs: cfg.OAuthClientRedirectURIs,
			Scopes:       cfg.OAuthClientScopes,
			Audience:     cfg.OAuthClientAudience,
			AccessTTL:    cfg.OAuthAccessTokenTTL,
			RefreshTTL:   cfg.OAuthRefreshTokenTTL,
		}})
		if err != nil {
			logger.Error("initialize oauth client registry", "error", err)
			os.Exit(1)
		}
		var oauthStore oauthservice.Store
		if redisOptions != nil {
			redisOAuthStore, err := oauthservice.NewRedisStore(redisOptions, cfg.OAuthRedisKeyPrefix)
			if err != nil {
				logger.Error("initialize oauth redis store", "error", err)
				os.Exit(1)
			}
			defer func() {
				if err := redisOAuthStore.Close(); err != nil {
					logger.Error("close oauth redis store", "error", err)
				}
			}()
			oauthStore = redisOAuthStore
		} else {
			oauthStore = oauthservice.NewMemoryStore()
		}
		oauthService, err := oauthservice.NewService(oauthservice.ServiceOptions{
			Registry:             registry,
			Store:                oauthStore,
			Sessions:             store,
			Signer:               signer,
			Issuer:               cfg.OAuthIssuer,
			CookieName:           cfg.SessionCookieName,
			LoginURL:             cfg.OAuthLoginURL,
			IdleTTL:              cfg.IdleTTL,
			AbsoluteTTL:          cfg.AbsoluteTTL,
			CodeTTL:              cfg.OAuthCodeTTL,
			ConsentTTL:           cfg.OAuthConsentTTL,
			RequiredEntitlements: cfg.OAuthRequiredEntitlements,
		})
		if err != nil {
			logger.Error("initialize oauth service", "error", err)
			os.Exit(1)
		}
		api.WithOAuth(oauthservice.NewHandler(oauthService, logger))
		logger.Info("oauth authorization server enabled",
			"issuer", cfg.OAuthIssuer,
			"client_id", cfg.OAuthClientID,
		)
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
