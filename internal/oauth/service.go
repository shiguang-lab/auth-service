package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/shiguanglab/auth-service/internal/identity"
	"github.com/shiguanglab/auth-service/internal/session"
)

// Errors surfaced to the HTTP layer. Every token endpoint failure is collapsed
// into ErrInvalidGrant by the handler so responses never disclose which check
// failed.
var (
	ErrInvalidGrant         = errors.New("invalid_grant")
	ErrInvalidClient        = errors.New("invalid_client")
	ErrNoSession            = errors.New("no active session")
	ErrMissingScope         = errors.New("missing entitlement")
	ErrAuthorizationPending = errors.New("authorization_pending")
	ErrAccessDenied         = errors.New("access_denied")
	ErrExpiredToken         = errors.New("expired_token")
)

const (
	codeEntropyBytes    = 32
	refreshEntropyBytes = 48
	pendingEntropyBytes = 32
	deviceTTL           = 10 * time.Minute
	devicePollInterval  = 5
	minVerifierLength   = 43
	maxVerifierLength   = 128
)

// ScopeDescriptions renders the consent screen copy for each supported scope.
var ScopeDescriptions = map[string]string{
	ScopeDocumentsRead:  "读取你的文档中心内容",
	ScopeDocumentsWrite: "创建、修改和删除你的文档",
	ScopeWebSession:     "在应用内打开已登录的拾光页面",
	ScopeOfflineAccess:  "在你关闭浏览器后仍保持登录（长期访问）",
}

type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type DevicePrompt struct {
	UserCode   string
	ClientName string
	Scopes     []ScopePrompt
	Redirect   string
}

type ServiceOptions struct {
	Registry     *Registry
	Store        Store
	Sessions     session.Store
	Signer       *identity.Signer
	Issuer       string
	CookieName   string
	CookieDomain string
	LoginURL     string
	WebAppURL    string
	IdleTTL      time.Duration
	AbsoluteTTL  time.Duration
	CodeTTL      time.Duration
	ConsentTTL   time.Duration
	// RequiredEntitlements must all be present on the user's session before a
	// scope can be granted.
	RequiredEntitlements []string
}

type Service struct {
	registry             *Registry
	store                Store
	sessions             session.Store
	signer               *identity.Signer
	issuer               string
	cookieName           string
	cookieDomain         string
	loginURL             string
	webAppURL            string
	idleTTL              time.Duration
	absoluteTTL          time.Duration
	codeTTL              time.Duration
	consentTTL           time.Duration
	requiredEntitlements []string
	now                  func() time.Time
}

func NewService(options ServiceOptions) (*Service, error) {
	if options.Registry == nil {
		return nil, errors.New("oauth registry is required")
	}
	if options.Store == nil {
		return nil, errors.New("oauth store is required")
	}
	if options.Sessions == nil {
		return nil, errors.New("session store is required")
	}
	if options.Signer == nil {
		return nil, errors.New("identity signer is required")
	}
	if strings.TrimSpace(options.Issuer) == "" {
		return nil, errors.New("oauth issuer is required")
	}
	if strings.TrimSpace(options.CookieName) == "" {
		return nil, errors.New("session cookie name is required")
	}
	if options.IdleTTL <= 0 || options.AbsoluteTTL <= 0 {
		return nil, errors.New("session TTLs must be positive")
	}
	if options.CodeTTL <= 0 || options.ConsentTTL <= 0 {
		return nil, errors.New("oauth code and consent TTLs must be positive")
	}
	if strings.TrimSpace(options.LoginURL) == "" {
		return nil, errors.New("oauth login URL is required")
	}
	return &Service{
		registry:             options.Registry,
		store:                options.Store,
		sessions:             options.Sessions,
		signer:               options.Signer,
		issuer:               options.Issuer,
		cookieName:           options.CookieName,
		cookieDomain:         options.CookieDomain,
		loginURL:             options.LoginURL,
		webAppURL:            strings.TrimRight(options.WebAppURL, "/"),
		idleTTL:              options.IdleTTL,
		absoluteTTL:          options.AbsoluteTTL,
		codeTTL:              options.CodeTTL,
		consentTTL:           options.ConsentTTL,
		requiredEntitlements: append([]string(nil), options.RequiredEntitlements...),
		now:                  time.Now,
	}, nil
}

type WebSessionResponse struct {
	URL       string `json:"url"`
	ExpiresIn int    `json:"expires_in"`
}

func (s *Service) CreateWebSessionTicket(ctx context.Context, accessToken, returnTo string) (WebSessionResponse, error) {
	binding, err := s.store.AccessBinding(ctx, hashToken(accessToken))
	if err != nil {
		return WebSessionResponse{}, ErrInvalidGrant
	}
	if _, err := s.sessionByID(ctx, binding.SessionCredential); err != nil {
		return WebSessionResponse{}, ErrInvalidGrant
	}
	policy, ok := s.registry.Client(binding.ClientID)
	if !ok {
		return WebSessionResponse{}, ErrInvalidGrant
	}
	base := policy.WebAppURL
	if base == "" {
		base = s.webAppURL
	}
	if strings.TrimSpace(returnTo) == "" {
		returnTo = base + "/"
	}
	parsed, err := url.Parse(returnTo)
	if err != nil {
		return WebSessionResponse{}, ErrInvalidGrant
	}
	expected, err := url.Parse(base)
	if err != nil || parsed.Scheme != expected.Scheme || parsed.Host != expected.Host {
		return WebSessionResponse{}, ErrInvalidGrant
	}
	ticket, err := randomToken(32)
	if err != nil {
		return WebSessionResponse{}, err
	}
	const ttl = time.Minute
	if err := s.store.PutWebTicket(ctx, ticket, WebSessionTicket{SessionCredential: binding.SessionCredential, ReturnTo: parsed.String()}, ttl); err != nil {
		return WebSessionResponse{}, err
	}
	return WebSessionResponse{URL: s.issuer + "/oauth/web-session?ticket=" + url.QueryEscape(ticket), ExpiresIn: int(ttl.Seconds())}, nil
}

func (s *Service) ConsumeWebSessionTicket(ctx context.Context, ticket string) (WebSessionTicket, error) {
	value, err := s.store.TakeWebTicket(ctx, ticket)
	if err != nil {
		return WebSessionTicket{}, ErrInvalidGrant
	}
	if _, err := s.sessionByID(ctx, value.SessionCredential); err != nil {
		return WebSessionTicket{}, ErrInvalidGrant
	}
	return value, nil
}

// Issuer is the token issuer identifier published in metadata and set as the
// `iss` claim.
func (s *Service) Issuer() string { return s.issuer }

// Registry exposes the registered clients to the HTTP layer.
func (s *Service) Registry() *Registry { return s.registry }

// AuthorizeRequest carries the validated query parameters of an authorization
// request.
type AuthorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Cookie              string
}

// AuthorizeOutcome is either a consent prompt or a redirect the browser must
// follow (a login detour for an unauthenticated user).
type AuthorizeOutcome struct {
	Consent  *ConsentPrompt
	Redirect string
}

// ConsentPrompt is the data rendered into the consent form.
type ConsentPrompt struct {
	PendingID  string
	ClientName string
	Scopes     []ScopePrompt
}

type ScopePrompt struct {
	Scope       string `json:"scope"`
	Description string `json:"description"`
}

// Authorize validates an authorization request and either returns a consent
// prompt or a redirect to the login page.
//
// Parameter failures are returned as plain errors and never redirect: an
// unchecked redirect target is exactly how an authorization endpoint becomes an
// open redirector.
func (s *Service) Authorize(ctx context.Context, request AuthorizeRequest) (AuthorizeOutcome, error) {
	policy, ok := s.registry.Client(request.ClientID)
	if !ok {
		return AuthorizeOutcome{}, fmt.Errorf("unknown client %q", request.ClientID)
	}
	if err := s.registry.ValidateRedirectURI(policy, request.RedirectURI); err != nil {
		return AuthorizeOutcome{}, err
	}
	if request.ResponseType != "code" {
		return AuthorizeOutcome{}, fmt.Errorf("unsupported response_type %q", request.ResponseType)
	}
	if !strings.EqualFold(strings.TrimSpace(request.CodeChallengeMethod), "S256") {
		return AuthorizeOutcome{}, errors.New("code_challenge_method must be S256")
	}
	if strings.TrimSpace(request.CodeChallenge) == "" {
		return AuthorizeOutcome{}, errors.New("code_challenge is required")
	}
	if strings.TrimSpace(request.State) == "" || len(request.State) > 512 {
		return AuthorizeOutcome{}, errors.New("state is required")
	}
	scopes := normaliseScope(request.Scope)
	if len(scopes) == 0 || !subsetOf(scopes, policy.Scopes) {
		return AuthorizeOutcome{}, fmt.Errorf("unsupported scope %q", request.Scope)
	}

	value, credential, err := s.activeSession(ctx, request.Cookie)
	if err != nil {
		if errors.Is(err, ErrNoSession) {
			return AuthorizeOutcome{Redirect: s.loginRedirect(request)}, nil
		}
		return AuthorizeOutcome{}, err
	}
	if !containsAll(value.Entitlements, s.requiredFor(policy)) {
		return AuthorizeOutcome{}, ErrMissingScope
	}

	pendingID, err := randomToken(pendingEntropyBytes)
	if err != nil {
		return AuthorizeOutcome{}, err
	}
	if err := s.store.PutPending(ctx, pendingID, PendingAuthorization{
		ClientID:          policy.ClientID,
		Subject:           value.Subject,
		SessionID:         value.AssertionSessionID,
		SessionCredential: credential,
		RedirectURI:       request.RedirectURI,
		Scope:             scopes,
		State:             request.State,
		CodeChallenge:     request.CodeChallenge,
		CreatedAt:         s.now(),
	}, s.consentTTL); err != nil {
		return AuthorizeOutcome{}, err
	}
	return AuthorizeOutcome{Consent: &ConsentPrompt{
		PendingID:  pendingID,
		ClientName: policy.Name,
		Scopes:     describeScopes(scopes),
	}}, nil
}

// Consent completes a pending authorization. The returned string is the URL the
// browser must be sent to next.
func (s *Service) Consent(ctx context.Context, pendingID string, allow bool, cookie string) (string, error) {
	// Read before consuming. The consent form is addressed by an unguessable
	// single-use ID, but it is also bound to the session that created it, so a
	// submission from another browser must be rejected without destroying the
	// legitimate user's pending request.
	pending, err := s.store.Pending(ctx, pendingID)
	if err != nil {
		return "", err
	}
	policy, ok := s.registry.Client(pending.ClientID)
	if !ok {
		return "", fmt.Errorf("unknown client %q", pending.ClientID)
	}
	value, _, err := s.activeSession(ctx, cookie)
	if err != nil {
		return "", err
	}
	if value.Subject != pending.Subject {
		return "", ErrNoSession
	}
	if _, err := s.store.TakePending(ctx, pendingID); err != nil {
		return "", err
	}
	if !allow {
		return redirectWithError(pending.RedirectURI, "access_denied", pending.State), nil
	}

	code, err := randomToken(codeEntropyBytes)
	if err != nil {
		return "", err
	}
	if err := s.store.PutCode(ctx, code, AuthorizationCode{
		ClientID:          policy.ClientID,
		Subject:           value.Subject,
		SessionID:         pending.SessionID,
		SessionCredential: pending.SessionCredential,
		DisplayName:       value.DisplayName,
		OrganizationID:    value.OrganizationID,
		Roles:             mergeRoles(value.PlatformRoles, value.Roles),
		Entitlements:      value.Entitlements,
		Scope:             pending.Scope,
		CodeChallenge:     pending.CodeChallenge,
		RedirectURI:       pending.RedirectURI,
		CreatedAt:         s.now(),
	}, s.codeTTL); err != nil {
		return "", err
	}
	return redirectWithCode(pending.RedirectURI, code, pending.State), nil
}

// StartDeviceAuthorization creates the two identifiers defined by RFC 8628.
// The long device code stays inside the plugin; the short user code is entered
// or carried in the verification URL shown in the browser.
func (s *Service) StartDeviceAuthorization(ctx context.Context, clientID, rawScope string) (DeviceAuthorizationResponse, error) {
	policy, ok := s.registry.Client(clientID)
	if !ok {
		return DeviceAuthorizationResponse{}, ErrInvalidClient
	}
	scopes := normaliseScope(rawScope)
	if len(scopes) == 0 || !subsetOf(scopes, policy.Scopes) {
		return DeviceAuthorizationResponse{}, ErrInvalidGrant
	}
	deviceCode, err := randomToken(32)
	if err != nil {
		return DeviceAuthorizationResponse{}, err
	}
	var userCode string
	for attempts := 0; attempts < 5; attempts++ {
		userCode, err = randomUserCode()
		if err != nil {
			return DeviceAuthorizationResponse{}, err
		}
		err = s.store.PutDevice(ctx, DeviceAuthorization{DeviceCode: hashToken(deviceCode), UserCode: userCode, ClientID: clientID, Scope: scopes, CreatedAt: s.now()}, deviceTTL)
		if err == nil {
			break
		}
	}
	if err != nil {
		return DeviceAuthorizationResponse{}, err
	}
	verification := s.issuer + "/oauth/device"
	return DeviceAuthorizationResponse{DeviceCode: deviceCode, UserCode: userCode, VerificationURI: verification, VerificationURIComplete: verification + "?user_code=" + url.QueryEscape(userCode), ExpiresIn: int(deviceTTL.Seconds()), Interval: devicePollInterval}, nil
}

// DevicePrompt validates the code and ensures the approving browser owns a
// live first-party session. An anonymous browser is redirected through the
// existing login flow and returns to the same verification page.
func (s *Service) DevicePrompt(ctx context.Context, userCode, cookie string) (DevicePrompt, error) {
	userCode = normaliseUserCode(userCode)
	grant, err := s.store.DeviceByUserCode(ctx, userCode)
	if err != nil {
		return DevicePrompt{}, err
	}
	if grant.Approved || grant.Denied {
		return DevicePrompt{}, ErrInvalidGrant
	}
	policy, ok := s.registry.Client(grant.ClientID)
	if !ok {
		return DevicePrompt{}, ErrInvalidClient
	}
	value, _, err := s.activeSession(ctx, cookie)
	if errors.Is(err, ErrNoSession) {
		returnTo := "/oauth/device?user_code=" + url.QueryEscape(userCode)
		separator := "?"
		if strings.Contains(s.loginURL, "?") {
			separator = "&"
		}
		return DevicePrompt{Redirect: s.loginURL + separator + url.Values{"return_to": {returnTo}}.Encode()}, nil
	}
	if err != nil {
		return DevicePrompt{}, err
	}
	if !containsAll(value.Entitlements, s.requiredFor(policy)) {
		return DevicePrompt{}, ErrMissingScope
	}
	return DevicePrompt{UserCode: userCode, ClientName: policy.Name, Scopes: describeScopes(grant.Scope)}, nil
}

func (s *Service) DecideDevice(ctx context.Context, userCode string, allow bool, cookie string) error {
	grant, err := s.store.DeviceByUserCode(ctx, normaliseUserCode(userCode))
	if err != nil {
		return err
	}
	if grant.Approved || grant.Denied {
		return ErrInvalidGrant
	}
	policy, ok := s.registry.Client(grant.ClientID)
	if !ok {
		return ErrInvalidClient
	}
	value, credential, err := s.activeSession(ctx, cookie)
	if err != nil {
		return err
	}
	if !containsAll(value.Entitlements, s.requiredFor(policy)) {
		return ErrMissingScope
	}
	grant.Denied = !allow
	grant.Approved = allow
	if allow {
		grant.Subject = value.Subject
		grant.SessionID = value.AssertionSessionID
		grant.SessionCredential = credential
		grant.DisplayName = value.DisplayName
		grant.OrganizationID = value.OrganizationID
		grant.Roles = mergeRoles(value.PlatformRoles, value.Roles)
		grant.Entitlements = value.Entitlements
	}
	return s.store.UpdateDevice(ctx, grant)
}

func (s *Service) requiredFor(policy ClientPolicy) []string {
	if len(policy.RequiredEntitlements) > 0 {
		return policy.RequiredEntitlements
	}
	return s.requiredEntitlements
}

func (s *Service) ExchangeDevice(ctx context.Context, deviceCode, clientID string) (TokenResponse, error) {
	policy, ok := s.registry.Client(clientID)
	if !ok {
		return TokenResponse{}, ErrInvalidClient
	}
	deviceCodeHash := hashToken(deviceCode)
	grant, err := s.store.Device(ctx, deviceCodeHash)
	if errors.Is(err, ErrDeviceNotFound) {
		return TokenResponse{}, ErrExpiredToken
	}
	if err != nil {
		return TokenResponse{}, err
	}
	if grant.ClientID != clientID {
		return TokenResponse{}, ErrInvalidGrant
	}
	if grant.Denied {
		_, _ = s.store.TakeDevice(ctx, deviceCodeHash)
		return TokenResponse{}, ErrAccessDenied
	}
	if !grant.Approved {
		return TokenResponse{}, ErrAuthorizationPending
	}
	grant, err = s.store.TakeDevice(ctx, deviceCodeHash)
	if err != nil {
		return TokenResponse{}, ErrExpiredToken
	}
	if _, err := s.sessionByID(ctx, grant.SessionCredential); err != nil {
		return TokenResponse{}, ErrInvalidGrant
	}
	return s.issue(ctx, policy, claimSet{Subject: grant.Subject, SessionID: grant.SessionID, SessionCredential: grant.SessionCredential, DisplayName: grant.DisplayName, OrganizationID: grant.OrganizationID, Roles: grant.Roles, Entitlements: grant.Entitlements, Scope: grant.Scope})
}

// TokenResponse is the RFC 6749 §5.1 token endpoint payload.
type TokenResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	RefreshToken string
	Scope        string
}

// ExchangeCode redeems an authorization code for a token pair.
func (s *Service) ExchangeCode(ctx context.Context, code, clientID, redirectURI, verifier string) (TokenResponse, error) {
	policy, ok := s.registry.Client(clientID)
	if !ok {
		return TokenResponse{}, ErrInvalidClient
	}
	stored, err := s.store.TakeCode(ctx, code)
	if err != nil {
		if errors.Is(err, ErrCodeNotFound) {
			return TokenResponse{}, ErrInvalidGrant
		}
		return TokenResponse{}, err
	}
	if stored.ClientID != clientID || stored.RedirectURI != redirectURI {
		return TokenResponse{}, ErrInvalidGrant
	}
	if !verifyPKCE(verifier, stored.CodeChallenge) {
		return TokenResponse{}, ErrInvalidGrant
	}
	if _, err := s.sessionByID(ctx, stored.SessionCredential); err != nil {
		return TokenResponse{}, ErrInvalidGrant
	}
	return s.issue(ctx, policy, claimSet{
		Subject:           stored.Subject,
		SessionID:         stored.SessionID,
		SessionCredential: stored.SessionCredential,
		DisplayName:       stored.DisplayName,
		OrganizationID:    stored.OrganizationID,
		Roles:             stored.Roles,
		Entitlements:      stored.Entitlements,
		Scope:             stored.Scope,
	})
}

// Refresh rotates a refresh token and returns a fresh token pair.
func (s *Service) Refresh(ctx context.Context, refreshToken, clientID string) (TokenResponse, error) {
	policy, ok := s.registry.Client(clientID)
	if !ok {
		return TokenResponse{}, ErrInvalidClient
	}
	stored, err := s.store.ConsumeRefresh(ctx, hashToken(refreshToken), s.now())
	if err != nil {
		if errors.Is(err, ErrRefreshInvalid) || errors.Is(err, ErrRefreshReused) {
			return TokenResponse{}, ErrInvalidGrant
		}
		return TokenResponse{}, err
	}
	if stored.ClientID != clientID {
		// A refresh token presented by the wrong client is a strong signal of
		// theft; destroy the family rather than merely refusing.
		_ = s.store.RevokeFamily(ctx, stored.FamilyID)
		return TokenResponse{}, ErrInvalidGrant
	}
	value, err := s.sessionByID(ctx, stored.SessionCredential)
	if err != nil {
		_ = s.store.RevokeFamily(ctx, stored.FamilyID)
		return TokenResponse{}, ErrInvalidGrant
	}
	return s.issue(ctx, policy, claimSet{
		Subject:           stored.Subject,
		SessionID:         stored.SessionID,
		SessionCredential: stored.SessionCredential,
		DisplayName:       value.DisplayName,
		OrganizationID:    value.OrganizationID,
		Roles:             mergeRoles(value.PlatformRoles, value.Roles),
		Entitlements:      value.Entitlements,
		Scope:             stored.Scope,
		FamilyID:          stored.FamilyID,
		Generation:        stored.Generation,
	})
}

// Revoke implements RFC 7009 for refresh tokens. Unknown tokens are a no-op so
// the endpoint cannot be used to probe for valid tokens.
func (s *Service) Revoke(ctx context.Context, token string) error {
	if strings.TrimSpace(token) == "" {
		return nil
	}
	return s.store.RevokeRefresh(ctx, hashToken(token))
}

// claimSet is the identity payload carried by a freshly minted token pair.
type claimSet struct {
	Subject           string
	SessionID         string
	SessionCredential string
	DisplayName       string
	OrganizationID    string
	Roles             []string
	Entitlements      []string
	Scope             []string
	FamilyID          string
	Generation        int
}

func (s *Service) issue(ctx context.Context, policy ClientPolicy, claims claimSet) (TokenResponse, error) {
	now := s.now()
	accessToken, err := s.signer.IssueAccessToken(identity.AccessToken{
		Audience:       policy.Audience,
		Subject:        claims.Subject,
		SessionID:      claims.SessionID,
		ClientID:       policy.ClientID,
		Scope:          joinScope(claims.Scope),
		DisplayName:    claims.DisplayName,
		OrganizationID: claims.OrganizationID,
		Roles:          claims.Roles,
		Entitlements:   claims.Entitlements,
		TTL:            policy.AccessTTL,
	}, now)
	if err != nil {
		return TokenResponse{}, fmt.Errorf("issue access token: %w", err)
	}
	if containsString(claims.Scope, ScopeWebSession) {
		if err := s.store.PutAccessBinding(ctx, hashToken(accessToken), SessionBinding{SessionCredential: claims.SessionCredential, ClientID: policy.ClientID}, policy.AccessTTL); err != nil {
			return TokenResponse{}, err
		}
	}
	response := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(policy.AccessTTL.Seconds()),
		Scope:       joinScope(claims.Scope),
	}
	if !containsString(claims.Scope, ScopeOfflineAccess) {
		return response, nil
	}
	refreshToken, err := randomToken(refreshEntropyBytes)
	if err != nil {
		return TokenResponse{}, err
	}
	familyID := claims.FamilyID
	if familyID == "" {
		familyID, err = randomToken(pendingEntropyBytes)
		if err != nil {
			return TokenResponse{}, err
		}
	}
	if err := s.store.PutRefresh(ctx, RefreshToken{
		TokenHash:         hashToken(refreshToken),
		FamilyID:          familyID,
		ClientID:          policy.ClientID,
		Subject:           claims.Subject,
		SessionID:         claims.SessionID,
		SessionCredential: claims.SessionCredential,
		Scope:             claims.Scope,
		Generation:        claims.Generation + 1,
		CreatedAt:         now,
	}, policy.RefreshTTL); err != nil {
		return TokenResponse{}, err
	}
	response.RefreshToken = refreshToken
	return response, nil
}

// activeSession resolves the session cookie exactly as the access gateway does:
// exactly one matching cookie, unrevoked, within both idle and absolute TTLs,
// and not a local development broker credential.
// activeSession returns the session and the store key it was loaded with. The
// key has to be retained: later phases re-check liveness with it, while tokens
// carry the public assertion id instead.
func (s *Service) activeSession(ctx context.Context, raw string) (session.Session, string, error) {
	credential, count := cookieValue(raw, s.cookieName)
	if count != 1 || credential == "" {
		return session.Session{}, "", ErrNoSession
	}
	value, err := s.sessionByID(ctx, credential)
	if err != nil {
		return session.Session{}, "", err
	}
	return value, credential, nil
}

func (s *Service) sessionByID(ctx context.Context, sessionID string) (session.Session, error) {
	if strings.TrimSpace(sessionID) == "" {
		return session.Session{}, ErrNoSession
	}
	value, err := s.sessions.Get(ctx, sessionID)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			return session.Session{}, ErrNoSession
		}
		return session.Session{}, err
	}
	if value.CredentialKind == session.CredentialKindLocalBroker {
		return session.Session{}, ErrNoSession
	}
	now := s.now()
	if !value.RevokedAt.IsZero() || value.Subject == "" || value.AssertionSessionID == "" {
		return session.Session{}, ErrNoSession
	}
	if now.Sub(value.LastSeenAt) > s.idleTTL || now.Sub(value.CreatedAt) > s.absoluteTTL {
		return session.Session{}, ErrNoSession
	}
	if !value.CredentialExpiresAt.IsZero() && !now.Before(value.CredentialExpiresAt) {
		return session.Session{}, ErrNoSession
	}
	return value, nil
}

func (s *Service) loginRedirect(request AuthorizeRequest) string {
	target := url.Values{}
	target.Set("response_type", request.ResponseType)
	target.Set("client_id", request.ClientID)
	target.Set("redirect_uri", request.RedirectURI)
	target.Set("scope", request.Scope)
	target.Set("state", request.State)
	target.Set("code_challenge", request.CodeChallenge)
	target.Set("code_challenge_method", request.CodeChallengeMethod)
	returnTo := "/oauth/authorize?" + target.Encode()

	login := url.Values{}
	login.Set("return_to", returnTo)
	separator := "?"
	if strings.Contains(s.loginURL, "?") {
		separator = "&"
	}
	return s.loginURL + separator + login.Encode()
}

func describeScopes(scopes []string) []ScopePrompt {
	result := make([]ScopePrompt, 0, len(scopes))
	for _, scope := range scopes {
		description := ScopeDescriptions[scope]
		if description == "" {
			description = scope
		}
		result = append(result, ScopePrompt{Scope: scope, Description: description})
	}
	return result
}

func redirectWithCode(redirectURI, code, state string) string {
	return appendQuery(redirectURI, url.Values{"code": {code}, "state": {state}})
}

func redirectWithError(redirectURI, code, state string) string {
	return appendQuery(redirectURI, url.Values{"error": {code}, "state": {state}})
}

func appendQuery(base string, values url.Values) string {
	parsed, err := url.Parse(base)
	if err != nil {
		return base
	}
	query := parsed.Query()
	for key, entries := range values {
		for _, entry := range entries {
			query.Set(key, entry)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func verifyPKCE(verifier, challenge string) bool {
	if len(verifier) < minVerifierLength || len(verifier) > maxVerifierLength {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) == 1
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func randomUserCode() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	for index := range buffer {
		buffer[index] = alphabet[int(buffer[index])%len(alphabet)]
	}
	return string(buffer[:4]) + "-" + string(buffer[4:]), nil
}

func normaliseUserCode(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "")
	if len(value) == 8 {
		return value[:4] + "-" + value[4:]
	}
	return value
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

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
