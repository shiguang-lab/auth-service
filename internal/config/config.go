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
	OIDCClientID               string
	OIDCClientSecret           string
	OIDCRedirectURL            string
	OIDCProviderIDs            map[string]string
	AllowedReturnOrigins       []string
	DefaultEntitlements        []string
	IdentityIssuer             string
	SigningKeyFile             string
	SigningKeyID               string
	IdentityTokenTTL           time.Duration
	IdleTTL                    time.Duration
	AbsoluteTTL                time.Duration
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
		OIDCClientID:               strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID")),
		OIDCClientSecret:           strings.TrimSpace(os.Getenv("OIDC_CLIENT_SECRET")),
		OIDCRedirectURL:            envOr("OIDC_REDIRECT_URL", "https://shiguanglab.com/api/auth/oidc/callback"),
		OIDCProviderIDs:            providerIDs,
		AllowedReturnOrigins:       splitCSV(envOr("ALLOWED_RETURN_ORIGINS", "https://shiguanglab.com,https://www.shiguanglab.com,https://opc.shiguanglab.com,https://huiguang.shiguanglab.com")),
		DefaultEntitlements:        splitCSV(envOr("DEFAULT_ENTITLEMENTS", "superagents:access,huiguang:access,platform:access")),
		IdentityIssuer:             envOr("IDENTITY_ISSUER", "https://auth.shiguanglab.com"),
		SigningKeyFile:             strings.TrimSpace(os.Getenv("IDENTITY_SIGNING_KEY_FILE")),
		SigningKeyID:               envOr("IDENTITY_KEY_ID", "dev-key"),
		IdentityTokenTTL:           identityTokenTTL,
		IdleTTL:                    idleTTL,
		AbsoluteTTL:                absoluteTTL,
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
	}
	for _, origin := range c.AllowedReturnOrigins {
		parsed, err := url.Parse(origin)
		validScheme := err == nil && (parsed.Scheme == "https" || (c.Environment != "production" && parsed.Scheme == "http"))
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
			(parsed.Path != "" && parsed.Path != "/") || !validScheme {
			return fmt.Errorf("invalid allowed return origin %q", origin)
		}
	}
	return nil
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
