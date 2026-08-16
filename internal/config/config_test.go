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

func TestAddProviderID(t *testing.T) {
	providers := map[string]string{"github": "github-idp"}
	if err := addProviderID(providers, "feishu", "feishu-idp"); err != nil {
		t.Fatal(err)
	}
	if providers["feishu"] != "feishu-idp" {
		t.Fatalf("provider IDs = %#v", providers)
	}
	if err := addProviderID(providers, "feishu", "different-idp"); err == nil {
		t.Fatal("expected a conflicting provider id to be rejected")
	}
}

func TestFeishuProviderRequiresAppID(t *testing.T) {
	cfg := Config{
		Environment:       "development",
		GatewayToken:      strings.Repeat("x", 32),
		SessionBackend:    "memory",
		SessionCookieName: "__Secure-sg_session",
		IdentityIssuer:    "https://auth.shiguanglab.com",
		SigningKeyID:      "key-1",
		IdentityTokenTTL:  time.Minute,
		IdleTTL:           time.Hour,
		AbsoluteTTL:       24 * time.Hour,
		OIDCProviderIDs:   map[string]string{"feishu": "feishu-idp"},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "FEISHU_APP_ID") {
		t.Fatalf("expected missing Feishu app ID error, got %v", err)
	}
	cfg.FeishuAppID = "cli_example"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate Feishu provider config: %v", err)
	}
}

func TestLocalBrokerRequiresFixedProductPolicyAndDefaultEntitlement(t *testing.T) {
	cfg := Config{
		Environment:             "development",
		GatewayToken:            strings.Repeat("x", 32),
		SessionBackend:          "memory",
		SessionCookieName:       "__Secure-sg_session",
		IdentityIssuer:          "https://shiguanglab.com",
		SigningKeyID:            "key-1",
		IdentityTokenTTL:        time.Minute,
		IdleTTL:                 time.Hour,
		AbsoluteTTL:             24 * time.Hour,
		DefaultEntitlements:     []string{"superagents:access"},
		LocalBrokerEnabled:      true,
		LocalBrokerProductID:    "asset-hub",
		LocalBrokerAudience:     "asset-hub-api",
		LocalBrokerEntitlements: []string{"asset-hub:access"},
		LocalBrokerTTL:          12 * time.Hour,
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "absent from DEFAULT_ENTITLEMENTS") {
		t.Fatalf("expected missing entitlement error, got %v", err)
	}
	cfg.DefaultEntitlements = append(cfg.DefaultEntitlements, "asset-hub:access")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate local broker config: %v", err)
	}
}
