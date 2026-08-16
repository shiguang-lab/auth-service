package authorize

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/shiguanglab/auth-service/internal/identity"
	"github.com/shiguanglab/auth-service/internal/session"
)

type Request struct {
	RequestID            string   `json:"request_id"`
	Method               string   `json:"method"`
	Scheme               string   `json:"scheme"`
	Host                 string   `json:"host"`
	Path                 string   `json:"path"`
	ClientIP             string   `json:"client_ip,omitempty"`
	Cookie               string   `json:"cookie,omitempty"`
	Authorization        string   `json:"authorization,omitempty"`
	Origin               string   `json:"origin,omitempty"`
	Accept               string   `json:"accept,omitempty"`
	ProductID            string   `json:"product_id"`
	Audience             string   `json:"audience"`
	Public               bool     `json:"public"`
	RequiredEntitlements []string `json:"required_entitlements,omitempty"`
}

type Response struct {
	Allow         bool     `json:"allow"`
	Status        int      `json:"status"`
	Reason        string   `json:"reason,omitempty"`
	IdentityToken string   `json:"identity_token,omitempty"`
	Location      string   `json:"location,omitempty"`
	SetCookies    []string `json:"set_cookies,omitempty"`
}

type Service struct {
	store             session.Store
	signer            *identity.Signer
	sessionCookieName string
	idleTTL           time.Duration
	absoluteTTL       time.Duration
	now               func() time.Time
}

func NewService(store session.Store, signer *identity.Signer, cookieName string, idleTTL, absoluteTTL time.Duration) *Service {
	return &Service{
		store:             store,
		signer:            signer,
		sessionCookieName: cookieName,
		idleTTL:           idleTTL,
		absoluteTTL:       absoluteTTL,
		now:               time.Now,
	}
}

func (s *Service) Decide(ctx context.Context, request Request) Response {
	if request.Public {
		return Response{Allow: true, Status: 200}
	}
	if request.Audience == "" || request.ProductID == "" {
		return Response{Allow: false, Status: 403, Reason: "invalid_route_identity"}
	}
	sessionID, count := cookieValue(request.Cookie, s.sessionCookieName)
	if count != 1 || sessionID == "" {
		reason := "session_missing"
		if count > 1 {
			reason = "duplicate_session_cookie"
		}
		return Response{Allow: false, Status: 401, Reason: reason}
	}
	return s.decideCredential(ctx, sessionID, request, false)
}

// DecideBroker validates a server-held local development broker and issues the
// same short-lived, audience-bound identity assertion used by access-gateway.
func (s *Service) DecideBroker(ctx context.Context, brokerToken string, request Request) Response {
	if brokerToken == "" {
		return Response{Allow: false, Status: 401, Reason: "broker_missing"}
	}
	return s.decideCredential(ctx, brokerToken, request, true)
}

func (s *Service) decideCredential(ctx context.Context, credential string, request Request, broker bool) Response {
	if request.Audience == "" || request.ProductID == "" {
		return Response{Allow: false, Status: 403, Reason: "invalid_route_identity"}
	}
	value, err := s.store.Get(ctx, credential)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			return Response{Allow: false, Status: 401, Reason: credentialReason(broker, "invalid")}
		}
		return Response{Allow: false, Status: 503, Reason: "session_store_unavailable"}
	}
	if broker != (value.CredentialKind == session.CredentialKindLocalBroker) {
		return Response{Allow: false, Status: 401, Reason: credentialReason(broker, "invalid")}
	}
	now := s.now()
	if !value.RevokedAt.IsZero() {
		return Response{Allow: false, Status: 401, Reason: "session_revoked"}
	}
	if value.Subject == "" ||
		value.AssertionSessionID == "" ||
		value.CreatedAt.IsZero() ||
		value.LastSeenAt.IsZero() ||
		value.AuthenticationTime.IsZero() {
		return Response{Allow: false, Status: 401, Reason: "session_invalid"}
	}
	if now.Sub(value.LastSeenAt) > s.idleTTL || now.Sub(value.CreatedAt) > s.absoluteTTL {
		return Response{Allow: false, Status: 401, Reason: credentialReason(broker, "expired")}
	}
	if !value.CredentialExpiresAt.IsZero() && !now.Before(value.CredentialExpiresAt) {
		return Response{Allow: false, Status: 401, Reason: credentialReason(broker, "expired")}
	}
	if !containsAll(value.Entitlements, request.RequiredEntitlements) {
		return Response{Allow: false, Status: 403, Reason: "missing_entitlement"}
	}
	token, err := s.signer.Issue(identity.Subject{
		Audience:              request.Audience,
		Subject:               value.Subject,
		SessionID:             value.AssertionSessionID,
		DisplayName:           value.DisplayName,
		OrganizationID:        value.OrganizationID,
		Roles:                 mergeRoles(value.PlatformRoles, value.Roles),
		Entitlements:          value.Entitlements,
		AuthenticationTime:    value.AuthenticationTime,
		AuthenticationMethods: value.AuthenticationMethods,
	}, now)
	if err != nil {
		return Response{Allow: false, Status: 503, Reason: "identity_issuer_unavailable"}
	}
	return Response{Allow: true, Status: 200, IdentityToken: token}
}

func credentialReason(broker bool, suffix string) string {
	if broker {
		return "broker_" + suffix
	}
	return "session_" + suffix
}

func cookieValue(raw, name string) (string, int) {
	var value string
	count := 0
	for _, part := range strings.Split(raw, ";") {
		cookieName, cookieValue, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || cookieName != name {
			continue
		}
		count++
		value = cookieValue
	}
	return value, count
}

// mergeRoles unions platform roles with context roles, preserving order.
func mergeRoles(platform, contextual []string) []string {
	if len(platform) == 0 {
		return contextual
	}
	merged := make([]string, 0, len(platform)+len(contextual))
	seen := make(map[string]struct{}, len(platform)+len(contextual))
	for _, group := range [][]string{platform, contextual} {
		for _, role := range group {
			if _, ok := seen[role]; ok {
				continue
			}
			seen[role] = struct{}{}
			merged = append(merged, role)
		}
	}
	return merged
}

func containsAll(actual, required []string) bool {
	if len(required) == 0 {
		return true
	}
	values := make(map[string]struct{}, len(actual))
	for _, value := range actual {
		values[value] = struct{}{}
	}
	for _, value := range required {
		if _, ok := values[value]; !ok {
			return false
		}
	}
	return true
}
