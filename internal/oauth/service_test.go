package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shiguanglab/auth-service/internal/identity"
	"github.com/shiguanglab/auth-service/internal/session"
)

const (
	testCookieName = "__Secure-sg_session"
	testClientID   = "obsidian-asset-hub"
	testRedirect   = "http://127.0.0.1:51234/callback"
	testState      = "3f9a1c2d4b5e6f708192a3b4c5d6e7f8"
	testSubject    = "zitadel-user-1"
	testEntitle    = "asset-hub:access"
)

var testSigner *identity.Signer

func TestMain(m *testing.M) {
	signer, err := identity.NewSigner("https://shiguanglab.com", "test-key", "", time.Minute)
	if err != nil {
		panic(err)
	}
	testSigner = signer
	os.Exit(m.Run())
}

// harness wires a service against in-memory stores and a controllable clock.
type harness struct {
	service    *Service
	sessions   *session.MemoryStore
	oauthStore *MemoryStore
	mu         sync.Mutex
	now        time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	registry, err := NewRegistry([]ClientPolicy{
		{
			ClientID:     testClientID,
			Name:         "知序资产中心 for Obsidian",
			RedirectURIs: []string{"http://127.0.0.1/callback", "http://[::1]/callback"},
			Scopes:       []string{ScopeDocumentsRead, ScopeDocumentsWrite, ScopeWebSession, ScopeOfflineAccess},
			Audience:     "asset-hub-api",
			AccessTTL:    15 * time.Minute,
			RefreshTTL:   30 * 24 * time.Hour,
		},
		{
			ClientID:             "other-client",
			Name:                 "另一个客户端",
			RedirectURIs:         []string{"http://127.0.0.1/callback"},
			Scopes:               []string{ScopeDocumentsRead},
			Audience:             "other-api",
			AccessTTL:            5 * time.Minute,
			RefreshTTL:           time.Hour,
			RequiredEntitlements: []string{"other:access"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sessions := session.NewMemoryStore()
	oauthStore := NewMemoryStore()
	service, err := NewService(ServiceOptions{
		Registry:             registry,
		Store:                oauthStore,
		Sessions:             sessions,
		Signer:               testSigner,
		Issuer:               "https://shiguanglab.com",
		CookieName:           testCookieName,
		LoginURL:             "https://shiguanglab.com/login",
		WebAppURL:            "https://doc.shiguanglab.com",
		IdleTTL:              12 * time.Hour,
		AbsoluteTTL:          7 * 24 * time.Hour,
		CodeTTL:              time.Minute,
		ConsentTTL:           10 * time.Minute,
		RequiredEntitlements: []string{testEntitle},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{service: service, sessions: sessions, oauthStore: oauthStore, now: time.Now()}
	service.now = h.clock
	return h
}

func TestDeviceAuthorizationAndWebSessionTicket(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	ctx := context.Background()
	started, err := h.service.StartDeviceAuthorization(ctx, testClientID, "documents:read web:session offline_access")
	if err != nil {
		t.Fatal(err)
	}
	if started.DeviceCode == "" || started.UserCode == "" || !strings.HasPrefix(started.VerificationURIComplete, "https://shiguanglab.com/oauth/device?") {
		t.Fatalf("unexpected response: %#v", started)
	}
	if _, err := h.oauthStore.Device(ctx, started.DeviceCode); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatal("the bearer device code must not be stored in plaintext")
	}
	if _, err := h.oauthStore.Device(ctx, hashToken(started.DeviceCode)); err != nil {
		t.Fatalf("hashed device grant is missing: %v", err)
	}
	if _, err := h.service.ExchangeDevice(ctx, started.DeviceCode, testClientID); !errors.Is(err, ErrAuthorizationPending) {
		t.Fatalf("pending exchange: %v", err)
	}
	prompt, err := h.service.DevicePrompt(ctx, started.UserCode, cookieFor("sess-1"))
	if err != nil {
		t.Fatal(err)
	}
	if prompt.ClientName == "" {
		t.Fatal("missing device prompt")
	}
	if err := h.service.DecideDevice(ctx, started.UserCode, true, cookieFor("sess-1")); err != nil {
		t.Fatal(err)
	}
	if err := h.service.DecideDevice(ctx, started.UserCode, false, cookieFor("sess-1")); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("a device decision must be final: %v", err)
	}
	tokens, err := h.service.ExchangeDevice(ctx, started.DeviceCode, testClientID)
	if err != nil {
		t.Fatal(err)
	}
	web, err := h.service.CreateWebSessionTicket(ctx, tokens.AccessToken, "https://doc.shiguanglab.com/assets/ast_1")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(web.URL)
	ticket := parsed.Query().Get("ticket")
	consumed, err := h.service.ConsumeWebSessionTicket(ctx, ticket)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.SessionCredential != "sess-1" || consumed.ReturnTo != "https://doc.shiguanglab.com/assets/ast_1" {
		t.Fatalf("unexpected ticket: %#v", consumed)
	}
	if _, err := h.service.ConsumeWebSessionTicket(ctx, ticket); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("ticket must be single-use: %v", err)
	}
}

func TestDeviceAuthorizationUsesClientEntitlements(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "asset-session", testSubject, []string{testEntitle})
	h.seedSession(t, "other-session", testSubject, []string{"other:access"})
	started, err := h.service.StartDeviceAuthorization(context.Background(), "other-client", ScopeDocumentsRead)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.DevicePrompt(context.Background(), started.UserCode, cookieFor("asset-session")); !errors.Is(err, ErrMissingScope) {
		t.Fatalf("asset entitlement must not approve another client: %v", err)
	}
	if _, err := h.service.DevicePrompt(context.Background(), started.UserCode, cookieFor("other-session")); err != nil {
		t.Fatalf("client entitlement should approve its own client: %v", err)
	}
}

func (h *harness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.now = h.now.Add(d)
}

func (h *harness) seedSession(t *testing.T, credential, subject string, entitlements []string) {
	t.Helper()
	now := h.clock()
	if err := h.sessions.Put(context.Background(), credential, session.Session{
		AssertionSessionID:    "sid-" + credential,
		Subject:               subject,
		DisplayName:           "测试用户",
		Entitlements:          entitlements,
		AuthenticationTime:    now.Add(-time.Minute),
		AuthenticationMethods: []string{"pwd"},
		CreatedAt:             now.Add(-time.Minute),
		LastSeenAt:            now,
	}); err != nil {
		t.Fatal(err)
	}
}

func cookieFor(credential string) string {
	return testCookieName + "=" + credential
}

func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	verifier = strings.Repeat("verifier-", 6) // 54 characters, inside the 43..128 range
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func defaultAuthorizeRequest(challenge string) AuthorizeRequest {
	return AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            testClientID,
		RedirectURI:         testRedirect,
		Scope:               "documents:read documents:write offline_access",
		State:               testState,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Cookie:              cookieFor("sess-1"),
	}
}

func queryParam(t *testing.T, raw, name string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return parsed.Query().Get(name)
}

func audienceContains(t *testing.T, value any, expected string) bool {
	t.Helper()
	switch typed := value.(type) {
	case string:
		return typed == expected
	case []any:
		for _, entry := range typed {
			if entry == expected {
				return true
			}
		}
	}
	return false
}

func decodeJWTPart(t *testing.T, token string, index int) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS, got %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		t.Fatalf("decode JWT segment %d: %v", index, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal JWT segment %d: %v", index, err)
	}
	return decoded
}

// authorizeAndConsent drives the interactive part of the flow and returns the
// redirect location.
func (h *harness) authorizeAndConsent(t *testing.T, request AuthorizeRequest, allow bool) string {
	t.Helper()
	outcome, err := h.service.Authorize(context.Background(), request)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if outcome.Consent == nil {
		t.Fatalf("expected a consent prompt, got redirect %q", outcome.Redirect)
	}
	location, err := h.service.Consent(context.Background(), outcome.Consent.PendingID, allow, request.Cookie)
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	return location
}

func TestAuthorizationCodeFlowIssuesOAuthAccessToken(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	verifier, challenge := pkcePair(t)

	location := h.authorizeAndConsent(t, defaultAuthorizeRequest(challenge), true)
	if got := queryParam(t, location, "state"); got != testState {
		t.Fatalf("state = %q, want %q", got, testState)
	}
	code := queryParam(t, location, "code")
	if code == "" {
		t.Fatalf("no code in redirect %q", location)
	}

	tokens, err := h.service.ExchangeCode(context.Background(), code, testClientID, testRedirect, verifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tokens.TokenType != "Bearer" {
		t.Fatalf("token_type = %q", tokens.TokenType)
	}
	if tokens.ExpiresIn != 900 {
		t.Fatalf("expires_in = %d, want 900", tokens.ExpiresIn)
	}
	if tokens.RefreshToken == "" {
		t.Fatal("offline_access was granted, so a refresh token is required")
	}
	if tokens.Scope != "documents:read documents:write offline_access" {
		t.Fatalf("scope = %q", tokens.Scope)
	}

	header := decodeJWTPart(t, tokens.AccessToken, 0)
	claims := decodeJWTPart(t, tokens.AccessToken, 1)
	// The JWS type must differ from the gateway identity assertion, otherwise
	// the two token classes would be interchangeable.
	if header["typ"] != "at+jwt" {
		t.Fatalf("typ = %v, want at+jwt", header["typ"])
	}
	if header["alg"] != "RS256" {
		t.Fatalf("alg = %v", header["alg"])
	}
	if claims["iss"] != "https://shiguanglab.com" {
		t.Fatalf("iss = %v", claims["iss"])
	}
	// A single audience is serialised as a one-element array by the JWS encoder,
	// which the resource server already tolerates.
	if !audienceContains(t, claims["aud"], "asset-hub-api") {
		t.Fatalf("aud = %v", claims["aud"])
	}
	if claims["sub"] != testSubject {
		t.Fatalf("sub = %v", claims["sub"])
	}
	if claims["sid"] != "sid-sess-1" {
		t.Fatalf("sid = %v, want the assertion session id", claims["sid"])
	}
	if claims["client_id"] != testClientID {
		t.Fatalf("client_id = %v", claims["client_id"])
	}
	if claims["nbf"] == nil {
		t.Fatal("nbf is required: the resource server enforces it")
	}
}

func TestAuthorizationCodeIsSingleUse(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	verifier, challenge := pkcePair(t)
	code := queryParam(t, h.authorizeAndConsent(t, defaultAuthorizeRequest(challenge), true), "code")

	if _, err := h.service.ExchangeCode(context.Background(), code, testClientID, testRedirect, verifier); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if _, err := h.service.ExchangeCode(context.Background(), code, testClientID, testRedirect, verifier); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("second exchange must fail, got %v", err)
	}
}

func TestExchangeRejectsMismatchedPKCE(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	_, challenge := pkcePair(t)
	code := queryParam(t, h.authorizeAndConsent(t, defaultAuthorizeRequest(challenge), true), "code")

	_, err := h.service.ExchangeCode(context.Background(), code, testClientID, testRedirect, strings.Repeat("wrong-", 8))
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid_grant, got %v", err)
	}
}

func TestExchangeRejectsRedirectMismatch(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	verifier, challenge := pkcePair(t)
	code := queryParam(t, h.authorizeAndConsent(t, defaultAuthorizeRequest(challenge), true), "code")

	_, err := h.service.ExchangeCode(context.Background(), code, testClientID, "http://127.0.0.1:51235/callback", verifier)
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid_grant, got %v", err)
	}
}

func TestAuthorizeRejectsPlainPKCE(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	request := defaultAuthorizeRequest("some-challenge")
	request.CodeChallengeMethod = "plain"

	if _, err := h.service.Authorize(context.Background(), request); err == nil {
		t.Fatal("plain PKCE must be rejected: it offers no protection")
	}
}

func TestAuthorizeRejectsUnregisteredRedirect(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	_, challenge := pkcePair(t)

	for _, candidate := range []string{
		"http://127.0.0.1.evil.com:51234/callback",
		"http://10.0.0.7:51234/callback",
		"http://127.0.0.1:51234/oauth/callback",
	} {
		t.Run(candidate, func(t *testing.T) {
			request := defaultAuthorizeRequest(challenge)
			request.RedirectURI = candidate
			if _, err := h.service.Authorize(context.Background(), request); err == nil {
				t.Fatalf("expected %q to be rejected", candidate)
			}
		})
	}
}

func TestAuthorizeRejectsUnknownClientAndScope(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	_, challenge := pkcePair(t)

	unknownClient := defaultAuthorizeRequest(challenge)
	unknownClient.ClientID = "not-registered"
	if _, err := h.service.Authorize(context.Background(), unknownClient); err == nil {
		t.Fatal("unknown client must be rejected")
	}

	unknownScope := defaultAuthorizeRequest(challenge)
	unknownScope.Scope = "documents:read documents:admin"
	if _, err := h.service.Authorize(context.Background(), unknownScope); err == nil {
		t.Fatal("ungranted scope must be rejected")
	}
}

func TestAuthorizeRedirectsToLoginWithoutSession(t *testing.T) {
	h := newHarness(t)
	_, challenge := pkcePair(t)
	request := defaultAuthorizeRequest(challenge)
	request.Cookie = ""

	outcome, err := h.service.Authorize(context.Background(), request)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if outcome.Consent != nil || outcome.Redirect == "" {
		t.Fatalf("expected a login redirect, got %#v", outcome)
	}
	parsed, err := url.Parse(outcome.Redirect)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Path != "/login" {
		t.Fatalf("login path = %q", parsed.Path)
	}
	returnTo := parsed.Query().Get("return_to")
	if !strings.HasPrefix(returnTo, "/oauth/authorize?") {
		t.Fatalf("return_to = %q, want the original authorization request", returnTo)
	}
	if !strings.Contains(returnTo, "client_id="+testClientID) {
		t.Fatalf("return_to lost the client id: %q", returnTo)
	}
}

func TestAuthorizeRejectsMissingEntitlement(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{"some-other:access"})
	_, challenge := pkcePair(t)

	_, err := h.service.Authorize(context.Background(), defaultAuthorizeRequest(challenge))
	if !errors.Is(err, ErrMissingScope) {
		t.Fatalf("expected ErrMissingScope, got %v", err)
	}
}

func TestConsentDeniedReturnsAccessDenied(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	_, challenge := pkcePair(t)

	location := h.authorizeAndConsent(t, defaultAuthorizeRequest(challenge), false)
	if got := queryParam(t, location, "error"); got != "access_denied" {
		t.Fatalf("error = %q, want access_denied", got)
	}
	if got := queryParam(t, location, "state"); got != testState {
		t.Fatalf("state = %q", got)
	}
	if queryParam(t, location, "code") != "" {
		t.Fatal("a denied consent must not produce a code")
	}
}

func TestConsentIsSingleUseAndBoundToSession(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	h.seedSession(t, "sess-2", "another-user", []string{testEntitle})
	_, challenge := pkcePair(t)

	outcome, err := h.service.Authorize(context.Background(), defaultAuthorizeRequest(challenge))
	if err != nil {
		t.Fatal(err)
	}
	pendingID := outcome.Consent.PendingID

	// A different browser (its own session cookie) must not be able to approve
	// someone else's pending request.
	if _, err := h.service.Consent(context.Background(), pendingID, true, cookieFor("sess-2")); !errors.Is(err, ErrNoSession) {
		t.Fatalf("expected a session mismatch, got %v", err)
	}

	if _, err := h.service.Consent(context.Background(), pendingID, true, cookieFor("sess-1")); err != nil {
		t.Fatalf("consent: %v", err)
	}
	if _, err := h.service.Consent(context.Background(), pendingID, true, cookieFor("sess-1")); !errors.Is(err, ErrPendingNotFound) {
		t.Fatalf("consent must be single use, got %v", err)
	}
}

func TestRefreshRotatesAndDetectsReplay(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	first := h.issueTokens(t)

	second, err := h.service.Refresh(context.Background(), first.RefreshToken, testClientID)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("refresh token must rotate on every use")
	}
	if second.AccessToken == first.AccessToken {
		t.Fatal("a new access token must be minted")
	}

	// Replaying the consumed token is treated as compromise: the whole family
	// dies, including the token issued a moment ago.
	if _, err := h.service.Refresh(context.Background(), first.RefreshToken, testClientID); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid_grant on replay, got %v", err)
	}
	if _, err := h.service.Refresh(context.Background(), second.RefreshToken, testClientID); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("the family must be revoked after a replay, got %v", err)
	}
}

func TestRefreshRejectedWhenSessionRevoked(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	tokens := h.issueTokens(t)

	if err := h.sessions.Revoke(context.Background(), "sess-1", h.clock()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Refresh(context.Background(), tokens.RefreshToken, testClientID); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid_grant, got %v", err)
	}
}

func TestRefreshRejectedForWrongClient(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	tokens := h.issueTokens(t)

	if _, err := h.service.Refresh(context.Background(), tokens.RefreshToken, "other-client"); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid_grant, got %v", err)
	}
	// The family is destroyed on a cross-client presentation.
	if _, err := h.service.Refresh(context.Background(), tokens.RefreshToken, testClientID); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("family should be revoked, got %v", err)
	}
}

func TestRevokeDestroysFamily(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	tokens := h.issueTokens(t)

	if err := h.service.Revoke(context.Background(), tokens.RefreshToken); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := h.service.Refresh(context.Background(), tokens.RefreshToken, testClientID); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid_grant after revocation, got %v", err)
	}
}

func TestRevokeUnknownTokenIsAccepted(t *testing.T) {
	h := newHarness(t)
	if err := h.service.Revoke(context.Background(), "never-issued"); err != nil {
		t.Fatalf("revoking an unknown token must succeed: %v", err)
	}
}

func TestAccessTokenRequiresLiveSessionAtExchange(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	verifier, challenge := pkcePair(t)
	code := queryParam(t, h.authorizeAndConsent(t, defaultAuthorizeRequest(challenge), true), "code")

	h.advance(13 * time.Hour) // beyond the 12h idle TTL
	if _, err := h.service.ExchangeCode(context.Background(), code, testClientID, testRedirect, verifier); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected invalid_grant for an idle session, got %v", err)
	}
}

func TestRefreshIssuesNoTokenWithoutOfflineAccess(t *testing.T) {
	h := newHarness(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	verifier, challenge := pkcePair(t)
	request := defaultAuthorizeRequest(challenge)
	request.Scope = "documents:read"

	code := queryParam(t, h.authorizeAndConsent(t, request, true), "code")
	tokens, err := h.service.ExchangeCode(context.Background(), code, testClientID, testRedirect, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if tokens.RefreshToken != "" {
		t.Fatal("a refresh token must only be issued for offline_access")
	}
	if tokens.Scope != "documents:read" {
		t.Fatalf("scope = %q", tokens.Scope)
	}
}

// issueTokens runs the full interactive flow with the default scope set.
func (h *harness) issueTokens(t *testing.T) TokenResponse {
	t.Helper()
	verifier, challenge := pkcePair(t)
	request := defaultAuthorizeRequest(challenge)
	code := queryParam(t, h.authorizeAndConsent(t, request, true), "code")
	tokens, err := h.service.ExchangeCode(context.Background(), code, testClientID, testRedirect, verifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return tokens
}
