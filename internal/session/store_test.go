package session

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestLegacySessionWithoutPlatformRoleRefreshTimestampDecodes(t *testing.T) {
	var value Session
	if err := json.Unmarshal([]byte(`{"assertion_session_id":"assert-1","subject":"user-1","platform_roles":["platform:points-admin"]}`), &value); err != nil {
		t.Fatal(err)
	}
	if value.Subject != "user-1" || !value.PlatformRolesRefreshedAt.IsZero() {
		t.Fatalf("legacy session decoded incorrectly: %+v", value)
	}
}

func TestUpdatePlatformRolesPreservesConcurrentSessionState(t *testing.T) {
	store := NewMemoryStore()
	now := time.Now().UTC()
	value := Session{
		Subject:        "user-1",
		OrganizationID: "org-new",
		Roles:          []string{"org:admin"},
		PlatformRoles:  []string{"platform:points-admin"},
		Entitlements:   []string{"platform:access"},
		CreatedAt:      now.Add(-time.Hour),
		LastSeenAt:     now,
	}
	if err := store.Put(context.Background(), "session-1", value); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(context.Background(), "session-1", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	updated, err := store.UpdatePlatformRoles(context.Background(), "session-1", "user-1", []string{"platform:points-auditor"}, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if updated.RevokedAt.IsZero() || updated.OrganizationID != "org-new" || len(updated.Roles) != 1 || updated.Roles[0] != "org:admin" {
		t.Fatalf("concurrent session state was overwritten: %+v", updated)
	}
	if len(updated.PlatformRoles) != 1 || updated.PlatformRoles[0] != "platform:points-auditor" {
		t.Fatalf("platform roles = %#v", updated.PlatformRoles)
	}
}
