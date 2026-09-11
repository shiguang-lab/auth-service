package oauth

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client types. Only public clients (no client_secret) are supported: the
// first-party native client authenticates with PKCE instead.
const ClientTypePublic = "public"

// Supported scopes.
const (
	ScopeDocumentsRead  = "documents:read"
	ScopeDocumentsWrite = "documents:write"
	ScopeWebSession     = "web:session"
	ScopeOfflineAccess  = "offline_access"
)

const redirectPath = "/callback"

// ClientPolicy is one statically registered first-party OAuth client.
//
// RedirectURIs are templates rather than literals. Each pins scheme, host and
// path but may leave the port out, in which case any port is accepted. RFC 8252
// §7.3 requires this for native clients, which cannot know in advance which
// port they will bind. A port may be pinned by including it, e.g.
// "http://127.0.0.1:27123/callback". Registering both the IPv4 and IPv6 loopback
// templates is the usual configuration.
type ClientPolicy struct {
	ClientID     string
	Name         string
	ClientType   string
	RedirectURIs []string
	Scopes       []string
	Audience     string
	AccessTTL    time.Duration
	RefreshTTL   time.Duration
	// RequiredEntitlements must all be present before this client can be approved.
	RequiredEntitlements []string
	// WebAppURL is the only origin this client may target during a web-session handoff.
	WebAppURL string

	redirects []redirectTarget
}

// redirectTarget is a parsed loopback redirect URI. An empty port means
// "any port".
type redirectTarget struct {
	scheme string
	host   string
	port   string
	path   string
}

// Registry resolves clients by ID and validates their redirect URIs.
type Registry struct {
	clients map[string]ClientPolicy
}

func NewRegistry(policies []ClientPolicy) (*Registry, error) {
	registry := &Registry{clients: make(map[string]ClientPolicy, len(policies))}
	for _, policy := range policies {
		policy.ClientID = strings.TrimSpace(policy.ClientID)
		policy.Name = strings.TrimSpace(policy.Name)
		policy.Audience = strings.TrimSpace(policy.Audience)
		policy.WebAppURL = strings.TrimRight(strings.TrimSpace(policy.WebAppURL), "/")
		policy.RedirectURIs = trimAll(policy.RedirectURIs)
		policy.Scopes = trimAll(policy.Scopes)
		policy.RequiredEntitlements = trimAll(policy.RequiredEntitlements)

		if policy.ClientID == "" {
			return nil, errors.New("oauth client id is required")
		}
		if _, duplicate := registry.clients[policy.ClientID]; duplicate {
			return nil, fmt.Errorf("duplicate oauth client %q", policy.ClientID)
		}
		if policy.ClientType == "" {
			policy.ClientType = ClientTypePublic
		}
		if policy.ClientType != ClientTypePublic {
			return nil, fmt.Errorf("oauth client %q: unsupported client type %q", policy.ClientID, policy.ClientType)
		}
		if policy.Name == "" {
			policy.Name = policy.ClientID
		}
		if policy.Audience == "" {
			return nil, fmt.Errorf("oauth client %q: audience is required", policy.ClientID)
		}
		if len(policy.Scopes) == 0 {
			return nil, fmt.Errorf("oauth client %q: at least one scope is required", policy.ClientID)
		}
		if policy.AccessTTL <= 0 {
			return nil, fmt.Errorf("oauth client %q: access token TTL must be positive", policy.ClientID)
		}
		if policy.RefreshTTL <= 0 {
			return nil, fmt.Errorf("oauth client %q: refresh token TTL must be positive", policy.ClientID)
		}
		for _, candidate := range policy.RedirectURIs {
			target, err := parseRedirectTemplate(candidate)
			if err != nil {
				return nil, fmt.Errorf("oauth client %q: %w", policy.ClientID, err)
			}
			policy.redirects = append(policy.redirects, target)
		}
		registry.clients[policy.ClientID] = policy
	}
	if len(registry.clients) == 0 {
		return nil, errors.New("at least one oauth client must be registered")
	}
	return registry, nil
}

// Client returns the policy for a client ID.
func (r *Registry) Client(clientID string) (ClientPolicy, bool) {
	policy, ok := r.clients[clientID]
	return policy, ok
}

// ScopesSupported is the union of every client's scopes, used by the metadata
// document.
func (r *Registry) ScopesSupported() []string {
	seen := make(map[string]struct{})
	var result []string
	for _, policy := range r.clients {
		for _, scope := range policy.Scopes {
			if _, ok := seen[scope]; ok {
				continue
			}
			seen[scope] = struct{}{}
			result = append(result, scope)
		}
	}
	return result
}

// ValidateRedirectURI reports whether raw matches one of the client's
// registered templates. The request must supply an explicit port; only its
// value is free-form.
func (r *Registry) ValidateRedirectURI(policy ClientPolicy, raw string) error {
	target, err := parseRedirectRequest(raw)
	if err != nil {
		return err
	}
	for _, expected := range policy.redirects {
		if target.scheme != expected.scheme || target.host != expected.host || target.path != expected.path {
			continue
		}
		if expected.port != "" && target.port != expected.port {
			continue
		}
		return nil
	}
	return fmt.Errorf("redirect_uri is not registered for client %q", policy.ClientID)
}

// parseRedirectTemplate validates a registered redirect URI. The port is
// optional here and, when omitted, acts as a wildcard.
func parseRedirectTemplate(raw string) (redirectTarget, error) {
	target, err := parseRedirectCommon(raw)
	if err != nil {
		return redirectTarget{}, err
	}
	if port := target.port; port != "" {
		if value, err := strconv.Atoi(port); err != nil || value < 1 || value > 65535 {
			return redirectTarget{}, fmt.Errorf("redirect_uri %q carries an invalid port", raw)
		}
	}
	return target, nil
}

// parseRedirectRequest validates a redirect URI supplied by a client. The port
// is required: an unauthenticated request must name the exact socket it is
// listening on.
func parseRedirectRequest(raw string) (redirectTarget, error) {
	if strings.TrimSpace(raw) == "" {
		return redirectTarget{}, errors.New("redirect_uri is required")
	}
	target, err := parseRedirectCommon(raw)
	if err != nil {
		return redirectTarget{}, err
	}
	if target.port == "" {
		return redirectTarget{}, fmt.Errorf("redirect_uri %q must carry an explicit port", raw)
	}
	if value, err := strconv.Atoi(target.port); err != nil || value < 1 || value > 65535 {
		return redirectTarget{}, fmt.Errorf("redirect_uri %q carries an invalid port", raw)
	}
	return target, nil
}

// parseRedirectCommon enforces the loopback shape. Host comparison runs on the
// parsed hostname rather than the raw string, otherwise
// "http://127.0.0.1.evil.com/callback" would satisfy a prefix check.
func parseRedirectCommon(raw string) (redirectTarget, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return redirectTarget{}, fmt.Errorf("redirect_uri %q is not a valid URI", raw)
	}
	if parsed.Scheme != "http" {
		return redirectTarget{}, fmt.Errorf("redirect_uri %q must use http", raw)
	}
	if parsed.User != nil {
		return redirectTarget{}, fmt.Errorf("redirect_uri %q must not carry userinfo", raw)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return redirectTarget{}, fmt.Errorf("redirect_uri %q must not carry a query or fragment", raw)
	}
	if parsed.Path != redirectPath {
		return redirectTarget{}, fmt.Errorf("redirect_uri %q must use the %s path", raw, redirectPath)
	}
	host := parsed.Hostname()
	if host != "127.0.0.1" && host != "::1" {
		return redirectTarget{}, fmt.Errorf("redirect_uri %q must target a loopback host", raw)
	}
	return redirectTarget{scheme: parsed.Scheme, host: host, port: parsed.Port(), path: parsed.Path}, nil
}

// normaliseScope splits a space-delimited scope string, dropping empties.
func normaliseScope(raw string) []string {
	var result []string
	for _, scope := range strings.Fields(raw) {
		result = append(result, scope)
	}
	return result
}

// subsetOf reports whether every requested scope is granted by allowed.
func subsetOf(requested, allowed []string) bool {
	granted := make(map[string]struct{}, len(allowed))
	for _, scope := range allowed {
		granted[scope] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := granted[scope]; !ok {
			return false
		}
	}
	return true
}

func trimAll(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func joinScope(scopes []string) string {
	return strings.Join(scopes, " ")
}
