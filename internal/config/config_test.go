package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDefaultAllowedReturnOriginsIncludePointsHost(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("GATEWAY_SHARED_TOKEN", strings.Repeat("g", 32))
	t.Setenv("SESSION_BACKEND", "memory")
	t.Setenv("SESSION_ENCRYPTION_KEY", "")
	t.Setenv("ALLOWED_RETURN_ORIGINS", "")
	t.Setenv("OIDC_PROVIDER_IDS", "")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(cfg.AllowedReturnOrigins, "https://points.shiguanglab.com") {
		t.Fatalf("allowed return origins = %#v", cfg.AllowedReturnOrigins)
	}
	if !slices.Equal(cfg.IAMRoleAdminOrigins, []string{"https://points.shiguanglab.com"}) {
		t.Fatalf("IAM role admin origins = %#v", cfg.IAMRoleAdminOrigins)
	}
	if cfg.IAMRoleCommandTTL != 30*24*time.Hour || cfg.IAMRoleCommandPrefix != "auth:iam-role-command:" {
		t.Fatalf("IAM role command config = %v %q", cfg.IAMRoleCommandTTL, cfg.IAMRoleCommandPrefix)
	}
}

func TestIAMRoleCommandJournalConfiguration(t *testing.T) {
	base := Config{
		Environment: "development", GatewayToken: strings.Repeat("x", 32), SessionBackend: "memory",
		SessionCookieName: "session", IdentityIssuer: "https://auth.shiguanglab.com", SigningKeyID: "key",
		IdentityTokenTTL: time.Minute, IdleTTL: time.Hour, AbsoluteTTL: 24 * time.Hour,
		IAMRoleAdminOrigins: []string{"http://127.0.0.1:3002"}, IAMRoleCommandPrefix: "auth:iam:", IAMRoleCommandTTL: 24 * time.Hour,
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	base.IAMRoleCommandTTL = time.Hour
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "IAM_ROLE_COMMAND_TTL") {
		t.Fatalf("TTL error = %v", err)
	}
	base.IAMRoleCommandTTL = 24 * time.Hour
	base.IAMRoleCommandPrefix = "auth:iam"
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "IAM_ROLE_COMMAND_PREFIX") {
		t.Fatalf("prefix error = %v", err)
	}
}

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
		PointsIdentityServiceToken: strings.Repeat("p", 40),
		OIDCClientID:               "client-id",
		OIDCClientSecret:           "client-secret",
		OIDCRedirectURL:            "https://shiguanglab.com/api/auth/oidc/callback",
		IAMRoleAdminOrigins:        []string{"https://points.shiguanglab.com"},
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

func TestProductionRejectsUnsafeIAMRoleAdminOrigin(t *testing.T) {
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
		PointsIdentityServiceToken: strings.Repeat("p", 40),
		OIDCClientID:               "client-id",
		OIDCClientSecret:           "client-secret",
		OIDCRedirectURL:            "https://shiguanglab.com/api/auth/oidc/callback",
		IdentityIssuer:             "https://auth.shiguanglab.com",
		SigningKeyFile:             "/run/secrets/identity.pem",
		SigningKeyID:               "key-1",
		IdentityTokenTTL:           time.Minute,
		IdleTTL:                    time.Hour,
		AbsoluteTTL:                24 * time.Hour,
		IAMRoleAdminOrigins:        []string{"http://points.shiguanglab.com"},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "IAM role admin origin") {
		t.Fatalf("expected unsafe IAM role admin origin error, got %v", err)
	}
}

func TestProductionRequiresIndependentPointsIdentityToken(t *testing.T) {
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
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "POINTS_IDENTITY_SERVICE_TOKEN") {
		t.Fatalf("expected missing Points identity token error, got %v", err)
	}
}

func TestParseProviderIDs(t *testing.T) {
	got, err := parseProviderIDs("github=383564589272399875, google = 12345")
	if err != nil {
		t.Fatal(err)
	}
	if got["github"] != "383564589272399875" || got["google"] != "12345" {
		t.Fatalf("provider IDs = %#v", got)
	}
}

func TestParseProviderIDsRejectsMalformedEntries(t *testing.T) {
	for _, input := range []string{"github", "github=", "github=id:with-colon", "github=one,github=two"} {
		t.Run(input, func(t *testing.T) {
			if _, err := parseProviderIDs(input); err == nil {
				t.Fatalf("parseProviderIDs(%q) succeeded", input)
			}
		})
	}
}
