package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var providerTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type Config struct {
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
	LocalBrokerTTL             time.Duration
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
		AllowedReturnOrigins:       splitCSV(envOr("ALLOWED_RETURN_ORIGINS", "https://shiguanglab.com,https://www.shiguanglab.com,https://opc.shiguanglab.com,https://huiguang.shiguanglab.com,https://points.shiguanglab.com")),
		IAMRoleAdminOrigins:        splitCSV(envOr("IAM_ROLE_ADMIN_ORIGINS", "https://points.shiguanglab.com")),
		IAMRoleCommandPrefix:       envOr("IAM_ROLE_COMMAND_PREFIX", "auth:iam-role-command:"),
		IAMRoleCommandTTL:          iamRoleCommandTTL,
		LocalIdentityFixture:       os.Getenv("LOCAL_IDENTITY_FIXTURE") == "1",
		LocalIdentityOrigin:        strings.TrimRight(strings.TrimSpace(os.Getenv("LOCAL_IDENTITY_ORIGIN")), "/"),
		LocalIdentityServiceToken:  strings.TrimSpace(os.Getenv("LOCAL_IDENTITY_SERVICE_TOKEN")),
		LocalIdentityRedisPrefix:   envOr("LOCAL_IDENTITY_REDIS_PREFIX", "auth:local-identity:"),
		DefaultEntitlements:        splitCSV(envOr("DEFAULT_ENTITLEMENTS", "superagents:access,huiguang:access,platform:access")),
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
		LocalBrokerTTL:             localBrokerTTL,
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
	if c.LocalBrokerEnabled {
		if !providerTokenPattern.MatchString(c.LocalBrokerProductID) ||
			!providerTokenPattern.MatchString(c.LocalBrokerAudience) {
			return errors.New("LOCAL_BROKER_PRODUCT_ID and LOCAL_BROKER_AUDIENCE must be configured tokens")
		}
		if c.LocalBrokerTTL <= 0 || c.LocalBrokerTTL > 24*time.Hour {
			return errors.New("LOCAL_BROKER_TTL must be greater than zero and at most 24h")
		}
		if len(c.LocalBrokerEntitlements) == 0 {
			return errors.New("LOCAL_BROKER_REQUIRED_ENTITLEMENTS must not be empty")
		}
		for _, required := range c.LocalBrokerEntitlements {
			if !contains(c.DefaultEntitlements, required) {
				return fmt.Errorf("local broker entitlement %q is absent from DEFAULT_ENTITLEMENTS", required)
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
	return nil
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
