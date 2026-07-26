package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr              string
	Environment       string
	GatewayToken      string
	SessionBackend    string
	SessionCookieName string
	IdentityIssuer    string
	SigningKeyFile    string
	SigningKeyID      string
	IdentityTokenTTL  time.Duration
	IdleTTL           time.Duration
	AbsoluteTTL       time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Addr:              envOr("AUTH_ADDR", ":8081"),
		Environment:       envOr("APP_ENV", "development"),
		GatewayToken:      strings.TrimSpace(os.Getenv("GATEWAY_SHARED_TOKEN")),
		SessionBackend:    envOr("SESSION_BACKEND", "memory"),
		SessionCookieName: envOr("SESSION_COOKIE_NAME", "__Secure-sg_session"),
		IdentityIssuer:    envOr("IDENTITY_ISSUER", "https://auth.shiguanglab.com"),
		SigningKeyFile:    strings.TrimSpace(os.Getenv("IDENTITY_SIGNING_KEY_FILE")),
		SigningKeyID:      envOr("IDENTITY_KEY_ID", "dev-key"),
		IdentityTokenTTL:  durationOr("IDENTITY_TOKEN_TTL", time.Minute),
		IdleTTL:           durationOr("SESSION_IDLE_TTL", 12*time.Hour),
		AbsoluteTTL:       durationOr("SESSION_ABSOLUTE_TTL", 7*24*time.Hour),
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if len(c.GatewayToken) < 32 {
		return errors.New("GATEWAY_SHARED_TOKEN must contain at least 32 characters")
	}
	if c.SessionCookieName == "" || c.IdentityIssuer == "" || c.SigningKeyID == "" {
		return errors.New("session cookie name, identity issuer and signing key id are required")
	}
	if c.IdentityTokenTTL <= 0 || c.IdentityTokenTTL > 2*time.Minute {
		return errors.New("IDENTITY_TOKEN_TTL must be greater than zero and at most 2m")
	}
	if c.IdleTTL <= 0 || c.AbsoluteTTL <= 0 || c.IdleTTL > c.AbsoluteTTL {
		return errors.New("session TTL configuration is invalid")
	}
	if c.Environment == "production" {
		if c.SessionBackend == "memory" {
			return errors.New("memory session backend is forbidden in production")
		}
		if c.SigningKeyFile == "" {
			return errors.New("IDENTITY_SIGNING_KEY_FILE is required in production")
		}
	}
	if c.SessionBackend != "memory" {
		return fmt.Errorf("session backend %q is not implemented yet", c.SessionBackend)
	}
	return nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func durationOr(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func Bool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
