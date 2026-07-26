package session

import (
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestRedisKeyDoesNotContainOpaqueSessionID(t *testing.T) {
	store, err := NewRedisStore(&redis.Options{Addr: "127.0.0.1:6379"}, "test:session:", time.Hour, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const sessionID = "opaque-browser-secret"
	key := store.key(sessionID)
	if strings.Contains(key, sessionID) {
		t.Fatalf("redis key leaked session id: %q", key)
	}
	if !strings.HasPrefix(key, "test:session:") {
		t.Fatalf("unexpected redis key: %q", key)
	}
}
