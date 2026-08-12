package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shiguanglab/auth-service/internal/authorize"
	"github.com/shiguanglab/auth-service/internal/identity"
	"github.com/shiguanglab/auth-service/internal/session"
)

const testGatewayToken = "0123456789abcdef0123456789abcdef"

func TestForwardAuthRejectsMissingAndDuplicateSessions(t *testing.T) {
	server, _ := newTestServer(t)
	for name, cookie := range map[string]string{
		"missing":   "",
		"duplicate": "__Secure-sg_session=one; __Secure-sg_session=two",
	} {
		t.Run(name, func(t *testing.T) {
			response := forwardAuthRequest(t, server, cookie, testGatewayToken)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestForwardAuthIssuesAudienceScopedIdentity(t *testing.T) {
	server, store := newTestServer(t)
	now := time.Now()
	if err := store.Put(context.Background(), "opaque-session", session.Session{
		AssertionSessionID:    "session-public-id",
		Subject:               "zitadel-user-id",
		OrganizationID:        "zitadel-org-id",
		Roles:                 []string{"platform_user"},
		Entitlements:          []string{"superagents:access"},
		AuthenticationTime:    now.Add(-time.Hour),
		AuthenticationMethods: []string{"pwd", "mfa"},
		CreatedAt:             now.Add(-time.Hour),
		LastSeenAt:            now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	response := forwardAuthRequest(
		t,
		server,
		"__Secure-sg_session=opaque-session",
		testGatewayToken,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	token := response.Header().Get(identityHeader)
	if token == "" {
		t.Fatal("identity header is empty")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts = %d", len(parts))
	}
	headerBody, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBody, &header); err != nil {
		t.Fatal(err)
	}
	if header["typ"] != "sg-identity+jwt" {
		t.Fatalf("typ = %#v", header["typ"])
	}
	claimsBody, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsBody, &claims); err != nil {
		t.Fatal(err)
	}
	audience, ok := claims["aud"].([]any)
	if !ok || len(audience) != 1 || audience[0] != "superagents-bff" || claims["sub"] != "zitadel-user-id" {
		t.Fatalf("claims = %#v", claims)
	}
}

func TestForwardAuthRequiresGatewayCredential(t *testing.T) {
	server, _ := newTestServer(t)
	response := forwardAuthRequest(t, server, "", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestAuthorizeJSONDecisionContract(t *testing.T) {
	server, store := newTestServer(t)
	now := time.Now()
	if err := store.Put(context.Background(), "opaque-session", session.Session{
		AssertionSessionID: "session-public-id",
		Subject:            "zitadel-user-id",
		Entitlements:       []string{"platform:access"},
		AuthenticationTime: now.Add(-time.Hour),
		CreatedAt:          now.Add(-time.Hour),
		LastSeenAt:         now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		input        authorize.Request
		wantStatus   int
		wantReason   string
		wantLocation bool
		wantIdentity bool
	}{
		{
			name: "allow issues identity",
			input: authorize.Request{
				Method: http.MethodGet, Host: "points.shiguanglab.com", Path: "/api/v1/me/points",
				ProductID: "points", Audience: "points-service", Cookie: "__Secure-sg_session=opaque-session",
				RequiredEntitlements: []string{"platform:access"},
			},
			wantStatus: http.StatusOK, wantIdentity: true,
		},
		{
			name: "missing session is structured unauthorized",
			input: authorize.Request{
				Method: http.MethodPost, Host: "points.shiguanglab.com", Path: "/api/v1/me/check-ins",
				ProductID: "points", Audience: "points-service", Accept: "application/json",
			},
			wantStatus: http.StatusUnauthorized, wantReason: "session_missing",
		},
		{
			name: "missing entitlement is structured forbidden",
			input: authorize.Request{
				Method: http.MethodGet, Host: "points.shiguanglab.com", Path: "/api/v1/admin/points/accounts",
				ProductID: "points", Audience: "points-service", Cookie: "__Secure-sg_session=opaque-session",
				RequiredEntitlements: []string{"platform:admin"},
			},
			wantStatus: http.StatusForbidden, wantReason: "missing_entitlement",
		},
		{
			name: "html navigation returns structured login redirect",
			input: authorize.Request{
				Method: http.MethodGet, Scheme: "https", Host: "points.shiguanglab.com", Path: "/ledger?limit=20",
				ProductID: "points-ui", Audience: "points-ui", Accept: "text/html",
			},
			wantStatus: http.StatusFound, wantReason: "session_missing", wantLocation: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := authorizeRequest(t, server, test.input, testGatewayToken)
			if response.Code != http.StatusOK {
				t.Fatalf("transport status = %d body=%s", response.Code, response.Body.String())
			}
			var decision authorize.Response
			if err := json.Unmarshal(response.Body.Bytes(), &decision); err != nil {
				t.Fatal(err)
			}
			if decision.Status != test.wantStatus || decision.Reason != test.wantReason {
				t.Fatalf("decision = %#v", decision)
			}
			if (decision.Location != "") != test.wantLocation {
				t.Fatalf("location = %q", decision.Location)
			}
			if (decision.IdentityToken != "") != test.wantIdentity {
				t.Fatalf("identity token presence = %t", decision.IdentityToken != "")
			}
		})
	}
}

func TestAuthorizeJSONRejectsInvalidTransportRequests(t *testing.T) {
	server, _ := newTestServer(t)

	unauthorized := authorizeRequest(t, server, authorize.Request{}, "wrong-token")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d body=%s", unauthorized.Code, unauthorized.Body.String())
	}

	for name, body := range map[string]string{
		"unknown field":  `{"method":"GET","unknown":true}`,
		"trailing value": `{} {}`,
		"oversized body": `{"path":"` + strings.Repeat("x", maxAuthorizeRequestBytes) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body))
			request.Header.Set(gatewayTokenHeader, testGatewayToken)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest && response.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			var decision authorize.Response
			if err := json.Unmarshal(response.Body.Bytes(), &decision); err != nil {
				t.Fatal(err)
			}
			if decision.Allow || decision.Status != response.Code || decision.Reason != "invalid_request" {
				t.Fatalf("decision = %#v", decision)
			}
		})
	}
}

func TestAuthorizeResponseJSONPreservesSessionCookieUpdates(t *testing.T) {
	response := httptest.NewRecorder()
	writeJSON(response, http.StatusOK, authorize.Response{
		Allow:      true,
		Status:     http.StatusOK,
		SetCookies: []string{"__Secure-sg_session=refreshed; Path=/; Secure; HttpOnly"},
	})

	var decision authorize.Response
	if err := json.Unmarshal(response.Body.Bytes(), &decision); err != nil {
		t.Fatal(err)
	}
	if len(decision.SetCookies) != 1 || !strings.HasPrefix(decision.SetCookies[0], "__Secure-sg_session=refreshed") {
		t.Fatalf("set cookies = %#v", decision.SetCookies)
	}
}

func newTestServer(t *testing.T) (http.Handler, *session.MemoryStore) {
	t.Helper()
	signer, err := identity.NewSigner("https://auth.shiguanglab.com", "test-key", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	store := session.NewMemoryStore()
	decision := authorize.NewService(store, signer, "__Secure-sg_session", 12*time.Hour, 7*24*time.Hour)
	server := NewServer(
		decision,
		signer,
		testGatewayToken,
		store.Ping,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	return server.Handler(), store
}

func forwardAuthRequest(t *testing.T, server http.Handler, cookie, gatewayToken string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/v1/forward-auth", nil)
	request.Header.Set(gatewayTokenHeader, gatewayToken)
	request.Header.Set("X-Forwarded-Method", http.MethodGet)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "opc.shiguanglab.com")
	request.Header.Set("X-Forwarded-Uri", "/workspaces")
	request.Header.Set("X-SG-Product-ID", "superagents")
	request.Header.Set("X-SG-Audience", "superagents-bff")
	request.Header.Set("X-SG-Required-Entitlements", "superagents:access")
	request.Header.Set("Cookie", cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}

func authorizeRequest(t *testing.T, server http.Handler, input authorize.Request, gatewayToken string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(string(body)))
	request.Header.Set(gatewayTokenHeader, gatewayToken)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}
