package authorize

import (
	"context"
	"testing"
	"time"

	"github.com/shiguanglab/auth-service/internal/identity"
	"github.com/shiguanglab/auth-service/internal/session"
)

func TestBrokerCredentialOnlyWorksThroughBrokerDecision(t *testing.T) {
	signer, err := identity.NewSigner("https://shiguanglab.com", "test-key", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	store := session.NewMemoryStore()
	now := time.Now().UTC()
	if err := store.Put(context.Background(), "opaque-broker", session.Session{
		AssertionSessionID:    "broker-session-id",
		Subject:               "user-1",
		Entitlements:          []string{"asset-hub:access"},
		AuthenticationTime:    now,
		AuthenticationMethods: []string{"pwd"},
		CreatedAt:             now,
		LastSeenAt:            now,
		CredentialKind:        session.CredentialKindLocalBroker,
		CredentialExpiresAt:   now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	service := NewService(store, signer, "__Secure-sg_session", 12*time.Hour, 24*time.Hour)
	request := Request{
		ProductID:            "asset-hub",
		Audience:             "asset-hub-api",
		RequiredEntitlements: []string{"asset-hub:access"},
	}

	if decision := service.Decide(context.Background(), Request{
		Cookie:               "__Secure-sg_session=opaque-broker",
		ProductID:            request.ProductID,
		Audience:             request.Audience,
		RequiredEntitlements: request.RequiredEntitlements,
	}); decision.Allow || decision.Status != 401 {
		t.Fatalf("browser decision=%#v", decision)
	}
	if decision := service.DecideBroker(context.Background(), "opaque-broker", request); !decision.Allow || decision.IdentityToken == "" {
		t.Fatalf("broker decision=%#v", decision)
	}
}

func TestBrowserSessionCannotBeUsedAsBroker(t *testing.T) {
	signer, err := identity.NewSigner("https://shiguanglab.com", "test-key", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	store := session.NewMemoryStore()
	now := time.Now().UTC()
	if err := store.Put(context.Background(), "browser-session", session.Session{
		AssertionSessionID: "browser-id", Subject: "user-1", AuthenticationTime: now,
		CreatedAt: now, LastSeenAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	service := NewService(store, signer, "__Secure-sg_session", time.Hour, 24*time.Hour)
	decision := service.DecideBroker(context.Background(), "browser-session", Request{
		ProductID: "asset-hub", Audience: "asset-hub-api",
	})
	if decision.Allow || decision.Reason != "broker_invalid" {
		t.Fatalf("decision=%#v", decision)
	}
}
