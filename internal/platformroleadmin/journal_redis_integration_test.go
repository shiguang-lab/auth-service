package platformroleadmin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestRedisCommandJournalLifecycleAndCAS(t *testing.T) {
	rawURL := os.Getenv("AUTH_TEST_REDIS_URL")
	if rawURL == "" {
		t.Skip("AUTH_TEST_REDIS_URL is not set")
	}
	options, err := redis.ParseURL(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("auth:test:iam-command:%d:", time.Now().UnixNano())
	journal, err := NewRedisCommandJournal(options, prefix, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		for _, pattern := range []string{prefix + "command:*", prefix + "status:*"} {
			keys, _ := journal.client.Keys(ctx, pattern).Result()
			if len(keys) > 0 {
				_ = journal.client.Del(ctx, keys...).Err()
			}
		}
		_ = journal.Close()
	})

	now := time.Now().UTC()
	command := commandFromChange(testRoleChange("redis-key", []string{PointsAdminRole}), now, 10*time.Millisecond)
	stored, created, err := journal.CreatePending(context.Background(), command, 24*time.Hour)
	if err != nil || !created || stored.Status != CommandPending {
		t.Fatalf("create=%#v created=%v err=%v", stored, created, err)
	}
	if ttl, err := journal.client.TTL(context.Background(), journal.commandKey(command.OperationID)).Result(); err != nil || ttl <= 23*time.Hour || ttl > 24*time.Hour {
		t.Fatalf("ttl=%v err=%v", ttl, err)
	}
	if ttl, err := journal.client.TTL(context.Background(), journal.indexKey(CommandPending)).Result(); err != nil || ttl < 90*24*time.Hour || ttl > commandIndexTTL {
		t.Fatalf("pending index ttl=%v err=%v", ttl, err)
	}
	raw, err := journal.client.Get(context.Background(), journal.commandKey(command.OperationID)).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), command.ActorSubject) || strings.Contains(string(raw), command.TargetUserID) {
		t.Fatal("Redis command value contains unencrypted identity fields")
	}
	replayed, created, err := journal.CreatePending(context.Background(), command, 24*time.Hour)
	if err != nil || created || replayed.OperationID != command.OperationID {
		t.Fatalf("replay=%#v created=%v err=%v", replayed, created, err)
	}
	conflict := command
	conflict.PayloadFingerprint = "different"
	if _, _, err := journal.CreatePending(context.Background(), conflict, 24*time.Hour); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict err=%v", err)
	}

	retryAt := now.Add(time.Second)
	var successes int
	var lock sync.Mutex
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := journal.ClaimRetry(context.Background(), command.OperationID, retryAt, time.Minute); err == nil {
				lock.Lock()
				successes++
				lock.Unlock()
			} else if !errors.Is(err, ErrChangeInProgress) && !errors.Is(err, ErrCommandConflict) {
				t.Errorf("claim error = %v", err)
			}
		}()
	}
	group.Wait()
	if successes != 1 {
		t.Fatalf("successful claims = %d", successes)
	}

	claimed, err := journal.Get(context.Background(), command.OperationID)
	if err != nil || claimed.Attempts != 2 {
		t.Fatalf("claimed=%#v err=%v", claimed, err)
	}
	user := User{ID: "target", LoginName: "target@shiguang", DisplayName: "Target", State: "ACTIVE", Roles: []string{PointsAdminRole}}
	finished, err := journal.MarkSucceeded(context.Background(), command.OperationID, claimed.Version, user.Roles, retryAt.Add(time.Second))
	if err != nil || finished.Status != CommandSucceeded || len(finished.ResultRoles) != 1 {
		t.Fatalf("finished=%#v err=%v", finished, err)
	}
	recoverable, err := journal.List(context.Background(), CommandFilter{Statuses: []CommandStatus{CommandPending, CommandReconcileRequired}, Limit: 10})
	if err != nil || len(recoverable) != 0 {
		t.Fatalf("recoverable=%#v err=%v", recoverable, err)
	}
}
