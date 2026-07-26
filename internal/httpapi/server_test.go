package httpapi

import (
	"bytes"
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

func TestAuthorizeRejectsMissingAndDuplicateSessions(t *testing.T) {
	server, _ := newTestServer(t)
	for name, cookie := range map[string]string{
		"missing":   "",
		"duplicate": "__Secure-sg_session=one; __Secure-sg_session=two",
	} {
		t.Run(name, func(t *testing.T) {
			result := authorizeRequest(t, server, authorize.Request{
				ProductID: "superagents",
				Audience:  "superagents-bff",
				Cookie:    cookie,
			})
			if result.Allow || result.Status != http.StatusUnauthorized {
				t.Fatalf("decision = %#v", result)
			}
		})
	}
}

func TestAuthorizeIssuesAudienceScopedIdentity(t *testing.T) {
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

	result := authorizeRequest(t, server, authorize.Request{
		ProductID:            "superagents",
		Audience:             "superagents-bff",
		Cookie:               "__Secure-sg_session=opaque-session",
		RequiredEntitlements: []string{"superagents:access"},
	})
	if !result.Allow || result.IdentityToken == "" {
		t.Fatalf("decision = %#v", result)
	}
	parts := strings.Split(result.IdentityToken, ".")
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
	if claims["aud"] != "superagents-bff" || claims["sub"] != "zitadel-user-id" {
		t.Fatalf("claims = %#v", claims)
	}
}

func TestAuthorizeRequiresGatewayCredential(t *testing.T) {
	server, _ := newTestServer(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader([]byte(`{"public":true}`)))
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", recorder.Code)
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
	server := NewServer(decision, signer, testGatewayToken, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return server.Handler(), store
}

func authorizeRequest(t *testing.T, server http.Handler, input authorize.Request) authorize.Response {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testGatewayToken)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("http status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var result authorize.Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
