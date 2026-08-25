package login

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shiguanglab/auth-service/internal/config"
	"github.com/shiguanglab/auth-service/internal/session"
)

type sessionRoleRefresher struct {
	role string
}

func (r sessionRoleRefresher) Refresh(_ context.Context, _ string, value session.Session) (session.Session, error) {
	value.PlatformRoles = []string{r.role}
	return value, nil
}

func TestSessionEndpointReturnsRefreshedPlatformRoles(t *testing.T) {
	now := time.Now().UTC()
	store := session.NewMemoryStore()
	if err := store.Put(context.Background(), "session-1", session.Session{
		AssertionSessionID: "assert-1",
		Subject:            "user-1",
		AuthenticationTime: now.Add(-time.Minute),
		CreatedAt:          now.Add(-time.Minute),
		LastSeenAt:         now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	service := (&Service{
		cfg: config.Config{
			SessionCookieName: "__Secure-sg_session",
			IdleTTL:           time.Hour,
			AbsoluteTTL:       24 * time.Hour,
		},
		sessions: store,
	}).WithPlatformRoleRefresher(sessionRoleRefresher{role: "platform:points-auditor"})
	request := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	request.AddCookie(&http.Cookie{Name: "__Secure-sg_session", Value: "session-1"})
	response := httptest.NewRecorder()
	service.Session(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		PlatformRoles []string `json:"platformRoles"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.PlatformRoles) != 1 || body.PlatformRoles[0] != "platform:points-auditor" {
		t.Fatalf("platform roles = %#v", body.PlatformRoles)
	}
}
