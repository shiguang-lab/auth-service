package oauth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryStoreCodeIsSingleUse(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.PutCode(ctx, "abc", AuthorizationCode{ClientID: "c", Subject: "s"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TakeCode(ctx, "abc"); err != nil {
		t.Fatalf("first redemption should succeed: %v", err)
	}
	if _, err := store.TakeCode(ctx, "abc"); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("second redemption must fail, got %v", err)
	}
}

func TestMemoryStoreCodeExpires(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.PutCode(ctx, "abc", AuthorizationCode{ClientID: "c"}, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := store.TakeCode(ctx, "abc"); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("expected an expired code, got %v", err)
	}
}

func TestMemoryStorePendingIsSingleUse(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.PutPending(ctx, "p1", PendingAuthorization{ClientID: "c", Subject: "s"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TakePending(ctx, "p1"); err != nil {
		t.Fatalf("first take should succeed: %v", err)
	}
	if _, err := store.TakePending(ctx, "p1"); !errors.Is(err, ErrPendingNotFound) {
		t.Fatalf("second take must fail, got %v", err)
	}
}

func TestMemoryStoreRefreshIsSingleUse(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Now()
	if err := store.PutRefresh(ctx, RefreshToken{TokenHash: "h1", FamilyID: "f1", ClientID: "c"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	record, err := store.ConsumeRefresh(ctx, "h1", now)
	if err != nil {
		t.Fatalf("first redemption should succeed: %v", err)
	}
	if record.FamilyID != "f1" || record.UsedAt.IsZero() {
		t.Fatalf("unexpected record %#v", record)
	}
	if _, err := store.ConsumeRefresh(ctx, "h1", now); !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("second redemption must report reuse, got %v", err)
	}
}

// A redeemed token must also be present in the family set, so replay detection
// can destroy every descendant rather than only the presented token.
func TestMemoryStoreReplayDestroysFamily(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Now()
	for _, hash := range []string{"h1", "h2"} {
		if err := store.PutRefresh(ctx, RefreshToken{TokenHash: hash, FamilyID: "f1", ClientID: "c"}, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.ConsumeRefresh(ctx, "h1", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeRefresh(ctx, "h1", now); !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("expected reuse detection, got %v", err)
	}
	if _, err := store.ConsumeRefresh(ctx, "h2", now); !errors.Is(err, ErrRefreshInvalid) {
		t.Fatalf("sibling token should have been revoked, got %v", err)
	}
}

func TestMemoryStoreRevokeRefreshDestroysFamily(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	now := time.Now()
	for _, hash := range []string{"h1", "h2"} {
		if err := store.PutRefresh(ctx, RefreshToken{TokenHash: hash, FamilyID: "f1", ClientID: "c"}, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RevokeRefresh(ctx, "h2"); err != nil {
		t.Fatal(err)
	}
	for _, hash := range []string{"h1", "h2"} {
		if _, err := store.ConsumeRefresh(ctx, hash, now); !errors.Is(err, ErrRefreshInvalid) {
			t.Fatalf("token %s should be revoked, got %v", hash, err)
		}
	}
}

func TestMemoryStoreRevokeUnknownTokenIsNoop(t *testing.T) {
	store := NewMemoryStore()
	if err := store.RevokeRefresh(context.Background(), "missing"); err != nil {
		t.Fatalf("revoking an unknown token must not fail: %v", err)
	}
}

func TestMemoryStoreRejectsEmptyIdentifiers(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.PutCode(ctx, " ", AuthorizationCode{}, time.Minute); err == nil {
		t.Fatal("expected an empty code to be rejected")
	}
	if err := store.PutPending(ctx, "", PendingAuthorization{}, time.Minute); err == nil {
		t.Fatal("expected an empty pending id to be rejected")
	}
	if err := store.PutRefresh(ctx, RefreshToken{}, time.Minute); err == nil {
		t.Fatal("expected an empty refresh hash to be rejected")
	}
}

// The store hands out copies: mutating a returned value must not corrupt the
// stored record.
func TestMemoryStoreReturnsCopies(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.PutPending(ctx, "p1", PendingAuthorization{Scope: []string{"a"}}, time.Minute); err != nil {
		t.Fatal(err)
	}
	first, err := store.TakePending(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}
	first.Scope[0] = "mutated"

	if err := store.PutPending(ctx, "p1", PendingAuthorization{Scope: []string{"a"}}, time.Minute); err != nil {
		t.Fatal(err)
	}
	second, err := store.TakePending(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if second.Scope[0] != "a" {
		t.Fatalf("stored record was mutated through a returned copy: %#v", second.Scope)
	}
}
