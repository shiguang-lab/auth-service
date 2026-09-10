package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	providerTokenPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	entitlementTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_:-]+$`)
)

type LocalBrokerProductPolicy struct {
	ProductID            string   `json:"productId"`
	Audience             string   `json:"audience"`
	RequiredEntitlements []string `json:"requiredEntitlements"`
}

type Config struct {
	// S3Endpoint is the MinIO/S3-compatible endpoint (host:port).
	S3Endpoint string
	// S3AccessKey is the MinIO access key.
	S3AccessKey string
	// S3SecretKey is the MinIO secret key.
	S3SecretKey string
	// S3Bucket is the S3 bucket name for avatar uploads.
	S3Bucket string
	// S3UseSSL indicates whether to use HTTPS for S3 connections.
	S3UseSSL bool
	// StaticBaseURL is the public-facing base URL for static resources (e.g. https://static.shiguanglab.com).
	StaticBaseURL              string
	Addr                       string
	Environment                string
	GatewayToken               string
	SessionBackend             string
	SessionCookieName          string
	SessionCookieDomain        string
	SessionEncryptionKey       []byte
	RedisURL                   string
	RedisKeyPrefix             string
	PublicOrigin               string
	ZitadelIssuer              string
	ZitadelInternalURL         string
	ZitadelPATFile             string
	ZitadelRegistrationPATFile string
	ZitadelOrganizationID      string
	ZitadelProjectID           string
	IdentityAPIToken           string
	PointsIdentityServiceToken string
	OIDCClientID               string
	OIDCClientSecret           string
	OIDCRedirectURL            string
	OIDCProviderIDs            map[string]string
	FeishuAppID                string
	AllowedReturnOrigins       []string
	IAMRoleAdminOrigins        []string
	IAMRoleCommandPrefix       string
	IAMRoleCommandTTL          time.Duration
	LocalIdentityFixture       bool
	LocalIdentityOrigin        string
	LocalIdentityServiceToken  string
	LocalIdentityRedisPrefix   string
	DefaultEntitlements        []string
	IdentityIssuer             string
	SigningKeyFile             string
	SigningKeyID               string
	IdentityTokenTTL           time.Duration
	IdleTTL                    time.Duration
	AbsoluteTTL                time.Duration
	LocalBrokerEnabled         bool
	LocalBrokerProductID       string
	LocalBrokerAudience        string
	LocalBrokerEntitlements    []string
	LocalBrokerPolicies        []LocalBrokerProductPolicy
	LocalBrokerTTL             time.Duration

	// OAuth 2.0 authorization server settings. Disabled by default; the router
	// only mounts the endpoints once a handler is supplied.
	OAuthEnabled              bool
	OAuthIssuer               string
	OAuthLoginURL             string
	OAuthClientID             string
	OAuthClientName           string
	OAuthClientRedirectURIs   []string
	OAuthClientScopes         []string
	OAuthClientAudience       string
	OAuthAccessTokenTTL       time.Duration
	OAuthRefreshTokenTTL      time.Duration
	OAuthCodeTTL              time.Duration
	OAuthConsentTTL           time.Duration
	OAuthRequiredEntitlements []string
	OAuthRedisKeyPrefix       string
}

func Load() (Config, error) {
	identityTokenTTL, err := durationOr("IDENTITY_TOKEN_TTL", time.Minute)
	if err != nil {
		return Config{}, err
	}
	idleTTL, err := durationOr("SESSION_IDLE_TTL", 12*time.Hour)
	if err != nil {
		return Config{}, err
	}
	absoluteTTL, err := durationOr("SESSION_ABSOLUTE_TTL", 7*24*time.Hour)
	if err != nil {
		return Config{}, err
	}
	iamRoleCommandTTL, err := durationOr("IAM_ROLE_COMMAND_TTL", 30*24*time.Hour)
	if err != nil {
		return Config{}, err
	}
	localBrokerTTL, err := durationOr("LOCAL_BROKER_TTL", 12*time.Hour)
	if err != nil {
		return Config{}, err
	}
	encryptionKey, err := decodeKey(os.Getenv("SESSION_ENCRYPTION_KEY"))
	if err != nil {
		return Config{}, err
	}
	providerIDs, err := parseProviderIDs(os.Getenv("OIDC_PROVIDER_IDS"))
	if err != nil {
		return Config{}, err
	}
	if err := addProviderID(providerIDs, "feishu", os.Getenv("FEISHU_IDP_ID")); err != nil {
		return Config{}, err
	}
	localBrokerPolicies, err := parseLocalBrokerPolicies(os.Getenv("LOCAL_BROKER_POLICIES"))
	if err != nil {
		return Config{}, err
	}
	oauthAccessTokenTTL, err := durationOr("OAUTH_ACCESS_TOKEN_TTL", 15*time.Minute)
	if err != nil {
		return Config{}, err
	}
	oauthRefreshTokenTTL, err := durationOr("OAUTH_REFRESH_TOKEN_TTL", 30*24*time.Hour)
	if err != nil {
		return Config{}, err
	}
	oauthCodeTTL, err := durationOr("OAUTH_CODE_TTL", time.Minute)
	if err != nil {
		return Config{}, err
	}
	oauthConsentTTL, err := durationOr("OAUTH_CONSENT_TTL", 10*time.Minute)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		Addr:                       envOr("AUTH_ADDR", ":8081"),
		Environment:                envOr("APP_ENV", "development"),
		GatewayToken:               strings.TrimSpace(os.Getenv("GATEWAY_SHARED_TOKEN")),
		SessionBackend:             envOr("SESSION_BACKEND", "memory"),
		SessionCookieName:          envOr("SESSION_COOKIE_NAME", "__Secure-sg_session"),
		SessionCookieDomain:        envOr("SESSION_COOKIE_DOMAIN", ".shiguanglab.com"),
		SessionEncryptionKey:       encryptionKey,
		RedisURL:                   strings.TrimSpace(os.Getenv("REDIS_URL")),
		RedisKeyPrefix:             envOr("REDIS_KEY_PREFIX", "auth:session:"),
		PublicOrigin:               strings.TrimRight(envOr("PUBLIC_ORIGIN", "https://shiguanglab.com"), "/"),
		ZitadelIssuer:              strings.TrimRight(envOr("ZITADEL_ISSUER", "https://sso.shiguanglab.com"), "/"),
		ZitadelInternalURL:         strings.TrimRight(envOr("ZITADEL_INTERNAL_URL", "http://zitadel-api:8080"), "/"),
		ZitadelPATFile:             strings.TrimSpace(os.Getenv("ZITADEL_PAT_FILE")),
		ZitadelRegistrationPATFile: strings.TrimSpace(os.Getenv("ZITADEL_REGISTRATION_PAT_FILE")),
		ZitadelOrganizationID:      strings.TrimSpace(os.Getenv("ZITADEL_ORGANIZATION_ID")),
		ZitadelProjectID:           strings.TrimSpace(os.Getenv("ZITADEL_PROJECT_ID")),
		IdentityAPIToken:           strings.TrimSpace(os.Getenv("IDENTITY_API_TOKEN")),
		PointsIdentityServiceToken: strings.TrimSpace(os.Getenv("POINTS_IDENTITY_SERVICE_TOKEN")),
		OIDCClientID:               strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID")),
		OIDCClientSecret:           strings.TrimSpace(os.Getenv("OIDC_CLIENT_SECRET")),
		OIDCRedirectURL:            envOr("OIDC_REDIRECT_URL", "https://shiguanglab.com/api/auth/oidc/callback"),
		OIDCProviderIDs:            providerIDs,
		FeishuAppID:                strings.TrimSpace(os.Getenv("FEISHU_APP_ID")),
		AllowedReturnOrigins:       splitCSV(envOr("ALLOWED_RETURN_ORIGINS", "https://shiguanglab.com,https://www.shiguanglab.com,https://opc.shiguanglab.com,https://huiguang.shiguanglab.com,https://point.shiguanglab.com,https://skills.shiguanglab.com")),
		IAMRoleAdminOrigins:        splitCSV(envOr("IAM_ROLE_ADMIN_ORIGINS", "https://shiguanglab.com,https://point.shiguanglab.com")),
		IAMRoleCommandPrefix:       envOr("IAM_ROLE_COMMAND_PREFIX", "auth:iam-role-command:"),
		IAMRoleCommandTTL:          iamRoleCommandTTL,
		LocalIdentityFixture:       os.Getenv("LOCAL_IDENTITY_FIXTURE") == "1",
		LocalIdentityOrigin:        strings.TrimRight(strings.TrimSpace(os.Getenv("LOCAL_IDENTITY_ORIGIN")), "/"),
		LocalIdentityServiceToken:  strings.TrimSpace(os.Getenv("LOCAL_IDENTITY_SERVICE_TOKEN")),
		LocalIdentityRedisPrefix:   envOr("LOCAL_IDENTITY_REDIS_PREFIX", "auth:local-identity:"),
		DefaultEntitlements:        splitCSV(envOr("DEFAULT_ENTITLEMENTS", "superagents:access,huiguang:access,platform:access")),
		S3Endpoint:                 envOr("SA_S3_ENDPOINT", "localhost:9000"),
		S3AccessKey:                envOr("SA_S3_ACCESS_KEY", "opc"),
		S3SecretKey:                os.Getenv("SA_S3_SECRET_KEY"),
		S3Bucket:                   envOr("SA_S3_BUCKET", "opc-skills"),
		S3UseSSL:                   envOr("SA_S3_SSL", "") == "true",
		StaticBaseURL:              strings.TrimRight(envOr("STATIC_BASE_URL", "https://static.shiguanglab.com"), "/"),
		IdentityIssuer:             envOr("IDENTITY_ISSUER", "https://auth.shiguanglab.com"),
		SigningKeyFile:             strings.TrimSpace(os.Getenv("IDENTITY_SIGNING_KEY_FILE")),
		SigningKeyID:               envOr("IDENTITY_KEY_ID", "dev-key"),
		IdentityTokenTTL:           identityTokenTTL,
		IdleTTL:                    idleTTL,
		AbsoluteTTL:                absoluteTTL,
		LocalBrokerEnabled:         strings.EqualFold(strings.TrimSpace(os.Getenv("LOCAL_BROKER_ENABLED")), "true"),
		LocalBrokerProductID:       strings.TrimSpace(os.Getenv("LOCAL_BROKER_PRODUCT_ID")),
		LocalBrokerAudience:        strings.TrimSpace(os.Getenv("LOCAL_BROKER_AUDIENCE")),
		LocalBrokerEntitlements:    splitCSV(os.Getenv("LOCAL_BROKER_REQUIRED_ENTITLEMENTS")),
		LocalBrokerPolicies:        localBrokerPolicies,
		LocalBrokerTTL:             localBrokerTTL,
		OAuthEnabled:               strings.EqualFold(strings.TrimSpace(os.Getenv("OAUTH_ENABLED")), "true"),
		OAuthIssuer:                strings.TrimRight(strings.TrimSpace(os.Getenv("OAUTH_ISSUER")), "/"),
		OAuthLoginURL:              strings.TrimSpace(os.Getenv("OAUTH_LOGIN_URL")),
		OAuthClientID:              envOr("OAUTH_CLIENT_ID", "obsidian-asset-hub"),
		OAuthClientName:            envOr("OAUTH_CLIENT_NAME", "知序资产中心 for Obsidian"),
		OAuthClientRedirectURIs:    splitCSV(envOr("OAUTH_CLIENT_REDIRECT_URIS", "http://127.0.0.1/callback,http://[::1]/callback")),
		OAuthClientScopes:          splitCSV(envOr("OAUTH_CLIENT_SCOPES", "documents:read,documents:write,offline_access")),
		OAuthClientAudience:        envOr("OAUTH_CLIENT_AUDIENCE", "asset-hub-api"),
		OAuthAccessTokenTTL:        oauthAccessTokenTTL,
		OAuthRefreshTokenTTL:       oauthRefreshTokenTTL,
		OAuthCodeTTL:               oauthCodeTTL,
		OAuthConsentTTL:            oauthConsentTTL,
		OAuthRequiredEntitlements:  splitCSV(envOr("OAUTH_REQUIRED_ENTITLEMENTS", "asset-hub:access")),
		OAuthRedisKeyPrefix:        envOr("OAUTH_REDIS_KEY_PREFIX", "auth:oauth:"),
	}
	if cfg.OAuthIssuer == "" {
		cfg.OAuthIssuer = cfg.PublicOrigin
	}
	if cfg.OAuthLoginURL == "" {
		cfg.OAuthLoginURL = cfg.PublicOrigin + "/login"
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// oauthKnownScopes is the closed set the authorization server can grant.
var oauthKnownScopes = []string{"documents:read", "documents:write", "offline_access"}

func (c Config) validateOAuth() error {
	if !c.OAuthEnabled {
		return nil
	}
	if !providerTokenPattern.MatchString(c.OAuthClientID) {
		return errors.New("OAUTH_CLIENT_ID must be a plain token")
	}
	if len(c.OAuthClientRedirectURIs) == 0 {
		return errors.New("OAUTH_CLIENT_REDIRECT_URIS must list at least one redirect URI")
	}
	if c.OAuthClientAudience == "" {
		return errors.New("OAUTH_CLIENT_AUDIENCE is required")
	}
	if !isAbsoluteURL(c.OAuthIssuer, c.Environment) {
		return errors.New("OAUTH_ISSUER must be an absolute http(s) URL")
	}
	if !isAbsoluteURL(c.OAuthLoginURL, c.Environment) {
		return errors.New("OAUTH_LOGIN_URL must be an absolute http(s) URL")
	}
	if len(c.OAuthClientScopes) == 0 {
		return errors.New("OAUTH_CLIENT_SCOPES must list at least one scope")
	}
	for _, scope := range c.OAuthClientScopes {
		if !contains(oauthKnownScopes, scope) {
			return fmt.Errorf("unsupported OAuth scope %q", scope)
		}
	}
	if len(c.OAuthRequiredEntitlements) == 0 {
		return errors.New("OAUTH_REQUIRED_ENTITLEMENTS must list at least one entitlement")
	}
	for _, entitlement := range c.OAuthRequiredEntitlements {
		if !entitlementTokenPattern.MatchString(entitlement) {
			return fmt.Errorf("invalid OAuth entitlement %q", entitlement)
		}
	}
	if c.OAuthAccessTokenTTL <= 0 || c.OAuthAccessTokenTTL > time.Hour {
		return errors.New("OAUTH_ACCESS_TOKEN_TTL must be greater than zero and at most 1h")
	}
	if c.OAuthRefreshTokenTTL <= 0 || c.OAuthRefreshTokenTTL > 90*24*time.Hour {
		return errors.New("OAUTH_REFRESH_TOKEN_TTL must be greater than zero and at most 2160h")
	}
	if c.OAuthCodeTTL <= 0 || c.OAuthCodeTTL > 10*time.Minute {
		return errors.New("OAUTH_CODE_TTL must be greater than zero and at most 10m")
	}
	if c.OAuthConsentTTL <= 0 || c.OAuthConsentTTL > 30*time.Minute {
		return errors.New("OAUTH_CONSENT_TTL must be greater than zero and at most 30m")
	}
	if c.OAuthRedisKeyPrefix == "" || !strings.HasSuffix(c.OAuthRedisKeyPrefix, ":") {
		return errors.New("OAUTH_REDIS_KEY_PREFIX must end with a colon")
	}
	return nil
}

func isAbsoluteURL(value, environment string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return parsed.Scheme == "https" || (environment != "production" && parsed.Scheme == "http")
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
	if c.LocalBrokerEnabled {
		if c.LocalBrokerTTL <= 0 || c.LocalBrokerTTL > 24*time.Hour {
			return errors.New("LOCAL_BROKER_TTL must be greater than zero and at most 24h")
		}
		policies := c.EffectiveLocalBrokerPolicies()
		if len(policies) == 0 {
			return errors.New("LOCAL_BROKER_POLICIES or the legacy single-product policy must be configured")
		}
		seen := make(map[string]struct{}, len(policies))
		for _, policy := range policies {
			if !providerTokenPattern.MatchString(policy.ProductID) ||
				!providerTokenPattern.MatchString(policy.Audience) {
				return errors.New("local broker productId and audience must be configured tokens")
			}
			if _, duplicate := seen[policy.ProductID]; duplicate {
				return fmt.Errorf("duplicate local broker product policy %q", policy.ProductID)
			}
			seen[policy.ProductID] = struct{}{}
			if len(policy.RequiredEntitlements) == 0 {
				return fmt.Errorf("local broker product %q must require at least one entitlement", policy.ProductID)
			}
			for _, required := range policy.RequiredEntitlements {
				if !entitlementTokenPattern.MatchString(required) {
					return fmt.Errorf("invalid local broker entitlement %q", required)
				}
				if !contains(c.DefaultEntitlements, required) {
					return fmt.Errorf("local broker entitlement %q is absent from DEFAULT_ENTITLEMENTS", required)
				}
			}
		}
	}
	switch c.SessionBackend {
	case "memory":
		if c.Environment == "production" {
			return errors.New("memory session backend is forbidden in production")
		}
	case "redis":
		if c.RedisURL == "" {
			return errors.New("REDIS_URL is required for the redis session backend")
		}
		if len(c.SessionEncryptionKey) != 32 {
			return errors.New("SESSION_ENCRYPTION_KEY must be a base64-encoded 32-byte key for redis")
		}
	default:
		return fmt.Errorf("unsupported session backend %q", c.SessionBackend)
	}
	if c.Environment == "production" && c.SigningKeyFile == "" {
		return errors.New("IDENTITY_SIGNING_KEY_FILE is required in production")
	}
	if c.Environment == "production" {
		if c.PublicOrigin == "" || c.ZitadelIssuer == "" || c.ZitadelInternalURL == "" {
			return errors.New("public origin and ZITADEL URLs are required in production")
		}
		if c.ZitadelPATFile == "" || c.ZitadelRegistrationPATFile == "" || c.ZitadelOrganizationID == "" ||
			c.OIDCClientID == "" || c.OIDCClientSecret == "" || c.OIDCRedirectURL == "" {
			return errors.New("ZITADEL login, registration and OIDC client configuration are required in production")
		}
		if c.ZitadelProjectID == "" {
			return errors.New("ZITADEL_PROJECT_ID is required in production")
		}
		if len(c.IdentityAPIToken) < 32 {
			return errors.New("IDENTITY_API_TOKEN must contain at least 32 characters in production")
		}
		if len(c.PointsIdentityServiceToken) < 32 {
			return errors.New("POINTS_IDENTITY_SERVICE_TOKEN must contain at least 32 characters in production")
		}
	}
	if c.LocalIdentityFixture {
		if c.Environment == "production" {
			return errors.New("LOCAL_IDENTITY_FIXTURE is forbidden in production")
		}
		if c.SessionBackend != "redis" {
			return errors.New("LOCAL_IDENTITY_FIXTURE requires the redis session backend")
		}
		parsed, err := url.Parse(c.LocalIdentityOrigin)
		if err != nil || parsed.Scheme != "http" || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
			return errors.New("LOCAL_IDENTITY_ORIGIN must be an exact localhost HTTP origin")
		}
		if len(c.LocalIdentityServiceToken) < 32 {
			return errors.New("LOCAL_IDENTITY_SERVICE_TOKEN must contain at least 32 characters")
		}
		if c.LocalIdentityRedisPrefix == "" || !strings.HasSuffix(c.LocalIdentityRedisPrefix, ":") {
			return errors.New("LOCAL_IDENTITY_REDIS_PREFIX must end with a colon")
		}
	}
	if c.FeishuAppID != "" && !providerTokenPattern.MatchString(c.FeishuAppID) {
		return errors.New("FEISHU_APP_ID contains invalid characters")
	}
	if _, enabled := c.OIDCProviderIDs["feishu"]; enabled && c.FeishuAppID == "" {
		return errors.New("FEISHU_APP_ID is required when the Feishu identity provider is enabled")
	}
	for _, origin := range c.AllowedReturnOrigins {
		if !validOrigin(origin, c.Environment) {
			return fmt.Errorf("invalid allowed return origin %q", origin)
		}
	}
	if len(c.IAMRoleAdminOrigins) == 0 {
		return errors.New("IAM_ROLE_ADMIN_ORIGINS must contain at least one origin")
	}
	for _, origin := range c.IAMRoleAdminOrigins {
		if !validOrigin(origin, c.Environment) {
			return fmt.Errorf("invalid IAM role admin origin %q", origin)
		}
	}
	if c.IAMRoleCommandTTL != 0 && (c.IAMRoleCommandTTL < 24*time.Hour || c.IAMRoleCommandTTL > 90*24*time.Hour) {
		return errors.New("IAM_ROLE_COMMAND_TTL must be between 24h and 2160h")
	}
	if c.IAMRoleCommandPrefix != "" && !strings.HasSuffix(c.IAMRoleCommandPrefix, ":") {
		return errors.New("IAM_ROLE_COMMAND_PREFIX must end with a colon")
	}
	if err := c.validateOAuth(); err != nil {
		return err
	}
	return nil
}

func (c Config) EffectiveLocalBrokerPolicies() []LocalBrokerProductPolicy {
	policies := c.LocalBrokerPolicies
	if len(policies) == 0 && (c.LocalBrokerProductID != "" || c.LocalBrokerAudience != "" || len(c.LocalBrokerEntitlements) > 0) {
		policies = []LocalBrokerProductPolicy{{
			ProductID:            c.LocalBrokerProductID,
			Audience:             c.LocalBrokerAudience,
			RequiredEntitlements: c.LocalBrokerEntitlements,
		}}
	}
	result := make([]LocalBrokerProductPolicy, 0, len(policies))
	for _, policy := range policies {
		policy.ProductID = strings.TrimSpace(policy.ProductID)
		policy.Audience = strings.TrimSpace(policy.Audience)
		policy.RequiredEntitlements = append([]string(nil), policy.RequiredEntitlements...)
		for index := range policy.RequiredEntitlements {
			policy.RequiredEntitlements[index] = strings.TrimSpace(policy.RequiredEntitlements[index])
		}
		result = append(result, policy)
	}
	return result
}

func parseLocalBrokerPolicies(raw string) ([]LocalBrokerProductPolicy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var policies []LocalBrokerProductPolicy
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policies); err != nil {
		return nil, fmt.Errorf("parse LOCAL_BROKER_POLICIES: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse LOCAL_BROKER_POLICIES: one JSON array is required")
	}
	return policies, nil
}
func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func validOrigin(origin, environment string) bool {
	parsed, err := url.Parse(origin)
	validScheme := err == nil && (parsed.Scheme == "https" || (environment != "production" && parsed.Scheme == "http"))
	return err == nil && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" &&
		(parsed.Path == "" || parsed.Path == "/") && validScheme
}
func decodeKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, errors.New("SESSION_ENCRYPTION_KEY must use standard base64")
	}
	if len(key) != 32 {
		return nil, errors.New("SESSION_ENCRYPTION_KEY must decode to exactly 32 bytes")
	}
	return key, nil
}

func splitCSV(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func parseProviderIDs(value string) (map[string]string, error) {
	providerIDs := make(map[string]string)
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("OIDC_PROVIDER_IDS entry %q must use provider=id format", entry)
		}
		provider, id := strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
		if !providerTokenPattern.MatchString(provider) || !providerTokenPattern.MatchString(id) {
			return nil, fmt.Errorf("OIDC_PROVIDER_IDS entry %q contains an invalid provider or id", entry)
		}
		if _, exists := providerIDs[provider]; exists {
			return nil, fmt.Errorf("OIDC_PROVIDER_IDS contains duplicate provider %q", provider)
		}
		providerIDs[provider] = id
	}
	return providerIDs, nil
}

func addProviderID(providerIDs map[string]string, provider, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if !providerTokenPattern.MatchString(value) {
		return fmt.Errorf("%s provider id %q is invalid", strings.ToUpper(provider), value)
	}
	if current, exists := providerIDs[provider]; exists && current != value {
		return fmt.Errorf("provider %q is configured more than once", provider)
	}
	providerIDs[provider] = value
	return nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func durationOr(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration: %w", name, err)
	}
	return parsed, nil
}
