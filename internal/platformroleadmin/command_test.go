package platformroleadmin

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeProviderWriter struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (p *fakeProviderWriter) SetManagedRoles(_ context.Context, target string, roles, _ []string) (User, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.err != nil {
		return User{}, p.err
	}
	return User{ID: target, LoginName: target + "@shiguang", DisplayName: target, State: "ACTIVE", Roles: append([]string(nil), roles...)}, nil
}

func TestDurableExecutorIdempotencyAndPayloadConflict(t *testing.T) {
	journal := NewMemoryCommandJournal()
	provider := &fakeProviderWriter{}
	executor := mustExecutor(t, journal, provider)
	change := testRoleChange("stable-key", []string{PointsAdminRole})

	first, err := executor.ApplyPointsRoleChange(context.Background(), change)
	if err != nil {
		t.Fatal(err)
	}
	second, err := executor.ApplyPointsRoleChange(context.Background(), change)
	if err != nil {
		t.Fatal(err)
	}
	if first.OperationID == "" || second.OperationID != first.OperationID || !second.Replayed {
		t.Fatalf("results = %#v %#v", first, second)
	}
	if provider.calls != 1 {
		t.Fatalf("provider calls = %d", provider.calls)
	}

	conflicting := change
	conflicting.AfterRoles = []string{PointsAuditorRole}
	if _, err := executor.ApplyPointsRoleChange(context.Background(), conflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict error = %v", err)
	}
}

func TestUnknownProviderOutcomeRequiresReconciliationAndControlledRetry(t *testing.T) {
	journal := NewMemoryCommandJournal()
	provider := &fakeProviderWriter{err: context.DeadlineExceeded}
	executor := mustExecutor(t, journal, provider)
	change := testRoleChange("reconcile-key", []string{PointsAuditorRole})

	if _, err := executor.ApplyPointsRoleChange(context.Background(), change); !errors.Is(err, ErrReconcileRequired) {
		t.Fatalf("error = %v", err)
	}
	manager := NewCommandManager("manager", []string{IAMManagerRole})
	commands, err := executor.ListRecoverableCommands(context.Background(), manager, 10)
	if err != nil || len(commands) != 1 || commands[0].Status != CommandReconcileRequired {
		t.Fatalf("commands = %#v err=%v", commands, err)
	}
	provider.err = nil
	result, err := executor.RetryCommand(context.Background(), manager, commands[0].OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if result.User.Roles[0] != PointsAuditorRole || provider.calls != 2 {
		t.Fatalf("result=%#v calls=%d", result, provider.calls)
	}
	stored, err := journal.Get(context.Background(), commands[0].OperationID)
	if err != nil || stored.Status != CommandSucceeded || stored.Attempts != 2 {
		t.Fatalf("stored=%#v err=%v", stored, err)
	}
}

func TestDefinitiveProviderFailureIsFailedAndCanBeRetriedOnlyByIAMManager(t *testing.T) {
	journal := NewMemoryCommandJournal()
	provider := &fakeProviderWriter{err: &ProviderError{Code: "provider_rejected", Definitive: true}}
	executor := mustExecutor(t, journal, provider)
	change := testRoleChange("failed-key", []string{PointsAdminRole})
	if _, err := executor.ApplyPointsRoleChange(context.Background(), change); !errors.Is(err, ErrCommandFailed) {
		t.Fatalf("error = %v", err)
	}
	operationID := commandFromChange(change, time.Now().UTC(), 30*time.Second).OperationID
	if _, err := executor.RetryCommand(context.Background(), NewCommandManager("points-admin", []string{PointsAdminRole}), operationID); !errors.Is(err, ErrManagerRequired) {
		t.Fatalf("non-manager retry error = %v", err)
	}
	provider.err = nil
	if _, err := executor.RetryCommand(context.Background(), NewCommandManager("iam-admin", []string{IAMManagerRole}), operationID); err != nil {
		t.Fatal(err)
	}
}

func TestActivePendingLeasePreventsConcurrentProviderCall(t *testing.T) {
	journal := NewMemoryCommandJournal()
	provider := &fakeProviderWriter{}
	executor := mustExecutor(t, journal, provider)
	change := testRoleChange("pending-key", []string{PointsAdminRole})
	command := commandFromChange(change, time.Now().UTC(), time.Minute)
	if _, created, err := journal.CreatePending(context.Background(), command, 24*time.Hour); err != nil || !created {
		t.Fatalf("create pending: created=%v err=%v", created, err)
	}
	if _, err := executor.RetryCommand(context.Background(), NewCommandManager("iam-admin", []string{IAMManagerRole}), command.OperationID); !errors.Is(err, ErrChangeInProgress) {
		t.Fatalf("retry error = %v", err)
	}
	if provider.calls != 0 {
		t.Fatalf("provider calls = %d", provider.calls)
	}
}

type failingResultJournal struct{ *MemoryCommandJournal }

func (j failingResultJournal) MarkSucceeded(context.Context, string, int64, []string, time.Time) (RoleCommand, error) {
	return RoleCommand{}, errors.New("redis write failed")
}
func (j failingResultJournal) MarkReconcileRequired(context.Context, string, int64, string, time.Time) (RoleCommand, error) {
	return RoleCommand{}, errors.New("redis write failed")
}

func TestResultPersistenceFailureLeavesDurablePendingCommand(t *testing.T) {
	base := NewMemoryCommandJournal()
	journal := failingResultJournal{base}
	executor := mustExecutor(t, journal, &fakeProviderWriter{})
	change := testRoleChange("result-failure", []string{PointsAdminRole})
	if _, err := executor.ApplyPointsRoleChange(context.Background(), change); !errors.Is(err, ErrReconcileRequired) {
		t.Fatalf("error = %v", err)
	}
	operationID := commandFromChange(change, time.Now().UTC(), 30*time.Second).OperationID
	stored, err := base.Get(context.Background(), operationID)
	if err != nil || stored.Status != CommandPending {
		t.Fatalf("stored=%#v err=%v", stored, err)
	}
}

func mustExecutor(t *testing.T, journal CommandJournal, provider ProviderRoleWriter) *DurableChangeExecutor {
	t.Helper()
	executor, err := NewDurableChangeExecutor(journal, provider, 30*24*time.Hour, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

func testRoleChange(key string, roles []string) RoleChange {
	return RoleChange{IdempotencyKey: key, ActorSubject: "iam-manager", TargetUserID: "target", BeforeRoles: nil, AfterRoles: roles, RequestID: "request-1", RequestedAt: time.Now().UTC()}
}

func TestPointsCommandFingerprintRemainsBackwardCompatible(t *testing.T) {
	legacy := testRoleChange("legacy-key", []string{PointsAdminRole})
	withScope := legacy
	withScope.ManagedRoles = []string{PointsAuditorRole, PointsAdminRole}
	legacyCommand := commandFromChange(legacy, time.Now().UTC(), 30*time.Second)
	scopedCommand := commandFromChange(withScope, time.Now().UTC(), 30*time.Second)
	if legacyCommand.PayloadFingerprint != scopedCommand.PayloadFingerprint {
		t.Fatalf("legacy=%s scoped=%s", legacyCommand.PayloadFingerprint, scopedCommand.PayloadFingerprint)
	}
}
