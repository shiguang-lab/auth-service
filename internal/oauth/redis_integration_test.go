package oauth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func newIntegrationStore(t *testing.T) *RedisStore {
	t.Helper()
	rawURL := strings.TrimSpace(os.Getenv("AUTH_TEST_REDIS_URL"))
	if rawURL == "" {
		t.Skip("AUTH_TEST_REDIS_URL is not set")
	}
	options, err := redis.ParseURL(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewRedisStore(options, fmt.Sprintf("auth:test:oauth:%d:", time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	return store
}

func TestRedisStoreCodeIsSingleUse(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()
	if err := store.PutCode(ctx, "code-1", AuthorizationCode{ClientID: "c", Subject: "s"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	taken, err := store.TakeCode(ctx, "code-1")
	if err != nil {
		t.Fatalf("first take: %v", err)
	}
	if taken.Subject != "s" {
		t.Fatalf("subject = %q", taken.Subject)
	}
	if _, err := store.TakeCode(ctx, "code-1"); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("second take must fail, got %v", err)
	}
}

func TestRedisStorePendingPeekDoesNotConsume(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()
	if err := store.PutPending(ctx, "p-1", PendingAuthorization{ClientID: "c", Subject: "s"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pending(ctx, "p-1"); err != nil {
		t.Fatalf("peek: %v", err)
	}
	if _, err := store.TakePending(ctx, "p-1"); err != nil {
		t.Fatalf("take after peek: %v", err)
	}
	if _, err := store.TakePending(ctx, "p-1"); !errors.Is(err, ErrPendingNotFound) {
		t.Fatalf("second take must fail, got %v", err)
	}
}

func TestRedisStoreRefreshRotationAndReplay(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()
	now := time.Now()
	for _, hash := range []string{"h-1", "h-2"} {
		if err := store.PutRefresh(ctx, RefreshToken{TokenHash: hash, FamilyID: "f-1", ClientID: "c"}, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.ConsumeRefresh(ctx, "h-1", now); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := store.ConsumeRefresh(ctx, "h-1", now); !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("expected reuse detection, got %v", err)
	}
	// The replay must have destroyed every sibling in the family.
	if _, err := store.ConsumeRefresh(ctx, "h-2", now); !errors.Is(err, ErrRefreshInvalid) {
		t.Fatalf("sibling should be revoked, got %v", err)
	}
}

func TestRedisStoreRevokeRefreshDestroysFamily(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()
	if err := store.PutRefresh(ctx, RefreshToken{TokenHash: "h-3", FamilyID: "f-2", ClientID: "c"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeRefresh(ctx, "h-3"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeRefresh(ctx, "h-3", time.Now()); !errors.Is(err, ErrRefreshInvalid) {
		t.Fatalf("expected the token to be revoked, got %v", err)
	}
}

func TestRedisStoreRejectsPrefixWithoutColon(t *testing.T) {
	options, err := redis.ParseURL("redis://127.0.0.1:6379/0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRedisStore(options, "auth:oauth"); err == nil {
		t.Fatal("a prefix without a trailing colon must be rejected")
	}
}
