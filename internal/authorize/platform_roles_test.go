package authorize

import (
	"context"
	"testing"
	"time"

	"github.com/shiguanglab/auth-service/internal/identity"
	"github.com/shiguanglab/auth-service/internal/session"
)

type testRoleRefresher struct {
	calls int
	role  string
}

func (r *testRoleRefresher) Refresh(_ context.Context, _ string, value session.Session) (session.Session, error) {
	r.calls++
	value.PlatformRoles = []string{r.role}
	return value, nil
}

func TestDecideRefreshesPlatformRolesBeforeIssuingIdentity(t *testing.T) {
	now := time.Now().UTC()
	store := session.NewMemoryStore()
	if err := store.Put(context.Background(), "session-1", session.Session{
		AssertionSessionID: "assert-1",
		Subject:            "user-1",
		Entitlements:       []string{"platform:access"},
		AuthenticationTime: now.Add(-time.Minute),
		CreatedAt:          now.Add(-time.Minute),
		LastSeenAt:         now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	signer, err := identity.NewSigner("https://auth.shiguanglab.com", "test-key", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	refresher := &testRoleRefresher{role: "platform:points-admin"}
	service := NewService(store, signer, "__Secure-sg_session", time.Hour, 24*time.Hour).
		WithPlatformRoleRefresher(refresher)
	decision := service.Decide(context.Background(), Request{
		Method: "GET", ProductID: "points", Audience: "points-service",
		Cookie: "__Secure-sg_session=session-1", RequiredEntitlements: []string{"platform:access"},
	})
	if !decision.Allow || decision.IdentityToken == "" || refresher.calls != 1 {
		t.Fatalf("decision = %+v, refresh calls = %d", decision, refresher.calls)
	}
}
