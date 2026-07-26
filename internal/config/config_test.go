package config

import (
	"strings"
	"testing"
	"time"
)

func TestProductionRejectsMemoryAndMissingSigningKey(t *testing.T) {
	cfg := Config{
		Environment:       "production",
		GatewayToken:      strings.Repeat("x", 32),
		SessionBackend:    "memory",
		SessionCookieName: "__Secure-sg_session",
		IdentityIssuer:    "https://auth.shiguanglab.com",
		SigningKeyID:      "key-1",
		IdentityTokenTTL:  time.Minute,
		IdleTTL:           time.Hour,
		AbsoluteTTL:       24 * time.Hour,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected production memory backend to be rejected")
	}
}

func TestProductionAcceptsRedisAndSigningKey(t *testing.T) {
	cfg := Config{
		Environment:                "production",
		GatewayToken:               strings.Repeat("x", 32),
		SessionBackend:             "redis",
		SessionCookieName:          "__Secure-sg_session",
		SessionEncryptionKey:       make([]byte, 32),
		RedisURL:                   "redis://redis:6379/0",
		PublicOrigin:               "https://shiguanglab.com",
		ZitadelIssuer:              "https://sso.shiguanglab.com",
		ZitadelInternalURL:         "http://zitadel-api:8080",
		ZitadelPATFile:             "/run/secrets/zitadel.pat",
		ZitadelRegistrationPATFile: "/run/secrets/zitadel-registration.pat",
		ZitadelOrganizationID:      "organization-id",
		ZitadelProjectID:           "project-id",
		IdentityAPIToken:           strings.Repeat("i", 40),
		OIDCClientID:               "client-id",
		OIDCClientSecret:           "client-secret",
		OIDCRedirectURL:            "https://shiguanglab.com/api/auth/oidc/callback",
		IdentityIssuer:             "https://auth.shiguanglab.com",
		SigningKeyFile:             "/run/secrets/identity.pem",
		SigningKeyID:               "key-1",
		IdentityTokenTTL:           time.Minute,
		IdleTTL:                    time.Hour,
		AbsoluteTTL:                24 * time.Hour,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate production redis config: %v", err)
	}
}
