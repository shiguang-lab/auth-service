package config

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDefaultOriginsIncludeDeployedProductsAndRoleManagers(t *testing.T) {
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
	if !slices.Contains(cfg.AllowedReturnOrigins, "https://point.shiguanglab.com") || !slices.Contains(cfg.AllowedReturnOrigins, "https://skills.shiguanglab.com") {
		t.Fatalf("allowed return origins = %#v", cfg.AllowedReturnOrigins)
	}
	if !slices.Equal(cfg.IAMRoleAdminOrigins, []string{"https://shiguanglab.com", "https://point.shiguanglab.com"}) {
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
		IAMRoleAdminOrigins:        []string{"https://point.shiguanglab.com"},
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
		IAMRoleAdminOrigins:        []string{"http://point.shiguanglab.com"},
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

func TestLocalIdentityFixtureValidation(t *testing.T) {
	base := Config{
		Environment: "development", GatewayToken: strings.Repeat("g", 32),
		SessionBackend: "redis", SessionCookieName: "sg_local_session",
		SessionEncryptionKey: make([]byte, 32), RedisURL: "redis://127.0.0.1:6379/0",
		IdentityIssuer: "http://auth-service:8081", SigningKeyID: "local-key",
		IdentityTokenTTL: time.Minute, IdleTTL: time.Hour, AbsoluteTTL: 24 * time.Hour,
		IAMRoleAdminOrigins:  []string{"http://127.0.0.1:18080"},
		LocalIdentityFixture: true, LocalIdentityOrigin: "http://127.0.0.1:18080",
		LocalIdentityServiceToken: strings.Repeat("l", 32), LocalIdentityRedisPrefix: "auth:local-test:",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid local identity fixture: %v", err)
	}

	production := base
	production.Environment = "production"
	production.SigningKeyFile = "/run/secrets/local-test.pem"
	production.PublicOrigin = "https://shiguanglab.com"
	production.ZitadelIssuer = "https://sso.shiguanglab.com"
	production.ZitadelInternalURL = "http://zitadel-api:8080"
	production.ZitadelPATFile = "/run/secrets/zitadel.pat"
	production.ZitadelRegistrationPATFile = "/run/secrets/zitadel-registration.pat"
	production.ZitadelOrganizationID = "org"
	production.ZitadelProjectID = "project"
	production.IdentityAPIToken = strings.Repeat("i", 32)
	production.PointsIdentityServiceToken = strings.Repeat("p", 32)
	production.OIDCClientID = "client"
	production.OIDCClientSecret = "secret"
	production.OIDCRedirectURL = "https://shiguanglab.com/api/auth/oidc/callback"
	if err := production.Validate(); err == nil || !strings.Contains(err.Error(), "forbidden in production") {
		t.Fatalf("production fixture error = %v", err)
	}

	remote := base
	remote.LocalIdentityOrigin = "http://auth.example.test"
	if err := remote.Validate(); err == nil || !strings.Contains(err.Error(), "localhost") {
		t.Fatalf("remote fixture origin error = %v", err)
	}
}

func TestLocalBrokerRequiresFixedProductPolicyAndDefaultEntitlement(t *testing.T) {
	cfg := Config{
		Environment: "development", GatewayToken: strings.Repeat("x", 32), SessionBackend: "memory",
		SessionCookieName: "session", IdentityIssuer: "https://auth.shiguanglab.com", SigningKeyID: "key",
		IdentityTokenTTL: time.Minute, IdleTTL: time.Hour, AbsoluteTTL: 24 * time.Hour,
		IAMRoleAdminOrigins: []string{"http://127.0.0.1:3002"},
		DefaultEntitlements: []string{"platform:access"}, LocalBrokerEnabled: true,
		LocalBrokerProductID: "asset-hub", LocalBrokerAudience: "asset-hub-api",
		LocalBrokerEntitlements: []string{"asset-hub:access"}, LocalBrokerTTL: 12 * time.Hour,
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "absent from DEFAULT_ENTITLEMENTS") {
		t.Fatalf("expected missing entitlement error, got %v", err)
	}
	cfg.DefaultEntitlements = append(cfg.DefaultEntitlements, "asset-hub:access")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate local broker config: %v", err)
	}
}

func TestLocalBrokerSupportsMultipleServerOwnedProductPolicies(t *testing.T) {
	t.Setenv("LOCAL_BROKER_POLICIES", `[
		{"productId":"asset-hub","audience":"asset-hub-api","requiredEntitlements":["asset-hub:access"]},
		{"productId":"opc","audience":"superagents-bff","requiredEntitlements":["superagents:access"]}
	]`)
	policies, err := parseLocalBrokerPolicies(os.Getenv("LOCAL_BROKER_POLICIES"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Environment: "development", GatewayToken: strings.Repeat("x", 32), SessionBackend: "memory",
		SessionCookieName: "session", IdentityIssuer: "https://auth.shiguanglab.com", SigningKeyID: "key",
		IdentityTokenTTL: time.Minute, IdleTTL: time.Hour, AbsoluteTTL: 24 * time.Hour,
		IAMRoleAdminOrigins: []string{"http://127.0.0.1:3002"},
		DefaultEntitlements: []string{"asset-hub:access", "superagents:access"}, LocalBrokerEnabled: true,
		LocalBrokerPolicies: policies, LocalBrokerTTL: 12 * time.Hour,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate multi-product broker config: %v", err)
	}
	cfg.LocalBrokerPolicies = append(cfg.LocalBrokerPolicies, cfg.LocalBrokerPolicies[0])
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate product error, got %v", err)
	}
}

func oauthBaseConfig() Config {
	return Config{
		Environment: "development", GatewayToken: strings.Repeat("x", 32), SessionBackend: "memory",
		SessionCookieName: "session", IdentityIssuer: "https://auth.shiguanglab.com", SigningKeyID: "key",
		IdentityTokenTTL: time.Minute, IdleTTL: time.Hour, AbsoluteTTL: 24 * time.Hour,
		IAMRoleAdminOrigins: []string{"http://127.0.0.1:3002"},
	}
}

func TestOAuthIsOptIn(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("GATEWAY_SHARED_TOKEN", strings.Repeat("g", 32))
	t.Setenv("SESSION_BACKEND", "memory")
	t.Setenv("OAUTH_ENABLED", "")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OAuthEnabled {
		t.Fatal("the OAuth authorization server must be opt-in")
	}
}

func TestOAuthDefaultsAreUsableWhenEnabled(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("GATEWAY_SHARED_TOKEN", strings.Repeat("g", 32))
	t.Setenv("SESSION_BACKEND", "memory")
	t.Setenv("OAUTH_ENABLED", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OAuthClientID != "obsidian-asset-hub" {
		t.Fatalf("client id = %q", cfg.OAuthClientID)
	}
	if cfg.OAuthIssuer != cfg.PublicOrigin {
		t.Fatalf("issuer = %q, want the public origin %q", cfg.OAuthIssuer, cfg.PublicOrigin)
	}
	if cfg.OAuthLoginURL != cfg.PublicOrigin+"/login" {
		t.Fatalf("login url = %q", cfg.OAuthLoginURL)
	}
	if len(cfg.OAuthClientRedirectURIs) != 0 {
		t.Fatalf("redirect uris = %#v", cfg.OAuthClientRedirectURIs)
	}
	if cfg.OAuthAccessTokenTTL != 15*time.Minute || cfg.OAuthRefreshTokenTTL != 30*24*time.Hour {
		t.Fatalf("token TTLs = %v / %v", cfg.OAuthAccessTokenTTL, cfg.OAuthRefreshTokenTTL)
	}
}

func TestOAuthValidationRejectsUnsafeConfiguration(t *testing.T) {
	cases := map[string]func(*Config){
		"malformed scope": func(c *Config) { c.OAuthClientScopes = []string{"documents admin"} },
		"long access ttl": func(c *Config) {
			c.OAuthAccessTokenTTL = 2 * time.Hour
		},
		"long code ttl":        func(c *Config) { c.OAuthCodeTTL = 30 * time.Minute },
		"plain client id":      func(c *Config) { c.OAuthClientID = "obsidian asset hub" },
		"no entitlement":       func(c *Config) { c.OAuthRequiredEntitlements = nil },
		"bad entitlement":      func(c *Config) { c.OAuthRequiredEntitlements = []string{"bad entitlement"} },
		"prefix without colon": func(c *Config) { c.OAuthRedisKeyPrefix = "auth:oauth" },
		"relative issuer":      func(c *Config) { c.OAuthIssuer = "/oauth" },
		"issuer with query":    func(c *Config) { c.OAuthIssuer = "https://shiguanglab.com/?next=1" },
		"missing audience":     func(c *Config) { c.OAuthClientAudience = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := oauthBaseConfig()
			cfg.OAuthEnabled = true
			cfg.OAuthIssuer = "https://shiguanglab.com"
			cfg.OAuthLoginURL = "https://shiguanglab.com/login"
			cfg.OAuthClientID = "obsidian-asset-hub"
			cfg.OAuthClientScopes = []string{"documents:read", "documents:write", "offline_access"}
			cfg.OAuthClientRedirectURIs = []string{"http://127.0.0.1/callback"}
			cfg.OAuthClientAudience = "asset-hub-api"
			cfg.OAuthRequiredEntitlements = []string{"asset-hub:access"}
			cfg.OAuthAccessTokenTTL = 15 * time.Minute
			cfg.OAuthRefreshTokenTTL = 30 * 24 * time.Hour
			cfg.OAuthCodeTTL = time.Minute
			cfg.OAuthConsentTTL = 10 * time.Minute
			cfg.OAuthRedisKeyPrefix = "auth:oauth:"
			if err := cfg.Validate(); err != nil {
				t.Fatalf("baseline must validate: %v", err)
			}
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected the configuration to be rejected")
			}
		})
	}
}

func TestOAuthClientsJSONSupportsIndependentNativeApps(t *testing.T) {
	clients, err := parseOAuthClients(`[
		{"clientId":"obsidian-asset-hub","name":"知序 for Obsidian","scopes":["documents:read","web:session"],"audience":"asset-hub-api","webAppUrl":"https://doc.shiguanglab.com","requiredEntitlements":["asset-hub:access"]},
		{"clientId":"desktop-notes","name":"拾光桌面端","scopes":["notes:read","offline_access"],"audience":"notes-api","requiredEntitlements":["notes:access"]}
	]`)
	if err != nil {
		t.Fatal(err)
	}
	cfg := oauthBaseConfig()
	cfg.OAuthEnabled = true
	cfg.OAuthIssuer = "https://shiguanglab.com"
	cfg.OAuthLoginURL = "https://shiguanglab.com/login"
	cfg.OAuthClients = clients
	cfg.OAuthAccessTokenTTL = 15 * time.Minute
	cfg.OAuthRefreshTokenTTL = 30 * 24 * time.Hour
	cfg.OAuthCodeTTL = time.Minute
	cfg.OAuthConsentTTL = 10 * time.Minute
	cfg.OAuthRedisKeyPrefix = "auth:oauth:"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate multi-client device configuration: %v", err)
	}
	if got := cfg.EffectiveOAuthClients(); len(got) != 2 || got[1].ClientID != "desktop-notes" {
		t.Fatalf("effective clients = %#v", got)
	}

	cfg.OAuthClients = append(cfg.OAuthClients, cfg.OAuthClients[0])
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate OAuth client") {
		t.Fatalf("expected duplicate client error, got %v", err)
	}
}
