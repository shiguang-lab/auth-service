package session

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestRedisUpdatePlatformRolesPreservesLatestSessionState(t *testing.T) {
	rawURL := strings.TrimSpace(os.Getenv("AUTH_TEST_REDIS_URL"))
	if rawURL == "" {
		t.Skip("AUTH_TEST_REDIS_URL is not set")
	}
	options, err := redis.ParseURL(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewRedisStore(options, fmt.Sprintf("auth:test:%d:", time.Now().UnixNano()), time.Hour, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	if err := store.Put(ctx, "session-1", Session{
		Subject:        "user-1",
		OrganizationID: "org-new",
		Roles:          []string{"org:admin"},
		PlatformRoles:  []string{"platform:points-admin"},
		Entitlements:   []string{"platform:access"},
		CreatedAt:      now.Add(-time.Hour),
		LastSeenAt:     now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Revoke(ctx, "session-1", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	updated, err := store.UpdatePlatformRoles(ctx, "session-1", "user-1", []string{"platform:points-auditor"}, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if updated.RevokedAt.IsZero() || updated.OrganizationID != "org-new" || len(updated.Roles) != 1 || updated.Roles[0] != "org:admin" {
		t.Fatalf("latest session state was overwritten: %+v", updated)
	}
}
