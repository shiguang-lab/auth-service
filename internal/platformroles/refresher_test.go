package platformroles

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/shiguanglab/auth-service/internal/session"
	"github.com/shiguanglab/auth-service/internal/zitadel"
)

type fakeDirectory struct {
	mu     sync.Mutex
	roles  []string
	err    error
	calls  int
	block  <-chan struct{}
	filter zitadel.AuthorizationFilter
}

func (f *fakeDirectory) ListAuthorizations(ctx context.Context, filter zitadel.AuthorizationFilter) ([]zitadel.Authorization, error) {
	f.mu.Lock()
	f.calls++
	f.filter = filter
	roles := append([]string(nil), f.roles...)
	err := f.err
	block := f.block
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	return []zitadel.Authorization{{Roles: roles}}, nil
}

func (f *fakeDirectory) set(roles []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roles = append([]string(nil), roles...)
	f.err = err
}

func (f *fakeDirectory) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeDirectory) lastFilter() zitadel.AuthorizationFilter {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.filter
}

func newTestRefresher(store session.Store, directory Directory, now *time.Time) *Refresher {
	refresher := New(store, directory, "platform-org", "platform-project", slog.New(slog.NewTextHandler(io.Discard, nil)))
	refresher.now = func() time.Time { return *now }
	return refresher
}

func seed(t *testing.T, store session.Store, id string, value session.Session) {
	t.Helper()
	if err := store.Put(context.Background(), id, value); err != nil {
		t.Fatal(err)
	}
}

func TestOldSessionRefreshesAndRoleChangesPropagate(t *testing.T) {
	now := time.Now().UTC()
	store := session.NewMemoryStore()
	directory := &fakeDirectory{roles: []string{"platform:points-admin"}}
	refresher := newTestRefresher(store, directory, &now)
	old := session.Session{Subject: "user-1", Entitlements: []string{"platform:access"}}
	seed(t, store, "session-1", old)

	refreshed, err := refresher.Refresh(context.Background(), "session-1", old)
	if err != nil {
		t.Fatal(err)
	}
	if len(refreshed.PlatformRoles) != 1 || refreshed.PlatformRoles[0] != "platform:points-admin" || refreshed.PlatformRolesRefreshedAt != now {
		t.Fatalf("initial refresh = %+v", refreshed)
	}
	filter := directory.lastFilter()
	if filter.UserID != "user-1" || filter.OrganizationID != "platform-org" || filter.ProjectID != "platform-project" || !filter.ActiveOnly {
		t.Fatalf("directory filter = %+v", filter)
	}

	directory.set([]string{"platform:points-auditor"}, nil)
	now = now.Add(DefaultTTL + time.Second)
	refreshed, err = refresher.Refresh(context.Background(), "session-1", refreshed)
	if err != nil {
		t.Fatal(err)
	}
	if len(refreshed.PlatformRoles) != 1 || refreshed.PlatformRoles[0] != "platform:points-auditor" {
		t.Fatalf("role replacement = %#v", refreshed.PlatformRoles)
	}

	directory.set(nil, nil)
	now = now.Add(DefaultTTL + time.Second)
	refreshed, err = refresher.Refresh(context.Background(), "session-1", refreshed)
	if err != nil {
		t.Fatal(err)
	}
	if len(refreshed.PlatformRoles) != 0 {
		t.Fatalf("revoked roles remain = %#v", refreshed.PlatformRoles)
	}
}

func TestDirectoryFailureClearsPrivilegesAndPreservesEntitlements(t *testing.T) {
	now := time.Now().UTC()
	store := session.NewMemoryStore()
	directory := &fakeDirectory{err: errors.New("directory unavailable")}
	refresher := newTestRefresher(store, directory, &now)
	value := session.Session{
		Subject:                  "user-1",
		PlatformRoles:            []string{"platform:points-admin"},
		PlatformRolesRefreshedAt: now.Add(-2 * DefaultTTL),
		Entitlements:             []string{"platform:access"},
	}
	seed(t, store, "session-1", value)

	refreshed, err := refresher.Refresh(context.Background(), "session-1", value)
	if err != nil {
		t.Fatal(err)
	}
	if len(refreshed.PlatformRoles) != 0 {
		t.Fatalf("stale privileged roles remain = %#v", refreshed.PlatformRoles)
	}
	if len(refreshed.Entitlements) != 1 || refreshed.Entitlements[0] != "platform:access" {
		t.Fatalf("ordinary entitlements changed = %#v", refreshed.Entitlements)
	}
}

func TestConcurrentRefreshUsesSingleDirectoryLookup(t *testing.T) {
	now := time.Now().UTC()
	store := session.NewMemoryStore()
	release := make(chan struct{})
	directory := &fakeDirectory{roles: []string{"platform:points-admin"}, block: release}
	refresher := newTestRefresher(store, directory, &now)
	value := session.Session{Subject: "user-1"}
	seed(t, store, "session-1", value)

	const callers = 8
	var wait sync.WaitGroup
	var ready sync.WaitGroup
	wait.Add(callers)
	ready.Add(callers)
	start := make(chan struct{})
	errorsFound := make(chan error, callers)
	for range callers {
		go func() {
			defer wait.Done()
			ready.Done()
			<-start
			_, err := refresher.Refresh(context.Background(), "session-1", value)
			errorsFound <- err
		}()
	}
	ready.Wait()
	close(start)
	for directory.callCount() == 0 {
		time.Sleep(time.Millisecond)
	}
	for {
		refresher.mu.Lock()
		joined := refresher.flights["user-1"] != nil && refresher.flights["user-1"].waiters == callers-1
		refresher.mu.Unlock()
		if joined {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls := directory.callCount(); calls != 1 {
		t.Fatalf("directory calls = %d, want 1", calls)
	}
}

func TestRefreshPreservesLatestOrganizationContext(t *testing.T) {
	now := time.Now().UTC()
	store := session.NewMemoryStore()
	directory := &fakeDirectory{roles: []string{"platform:points-auditor"}}
	refresher := newTestRefresher(store, directory, &now)
	stale := session.Session{Subject: "user-1", OrganizationID: "org-old", Roles: []string{"org:viewer"}}
	latest := stale
	latest.OrganizationID = "org-new"
	latest.Roles = []string{"org:admin"}
	seed(t, store, "session-1", latest)

	refreshed, err := refresher.Refresh(context.Background(), "session-1", stale)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.OrganizationID != "org-new" || len(refreshed.Roles) != 1 || refreshed.Roles[0] != "org:admin" {
		t.Fatalf("organization context was overwritten = %+v", refreshed)
	}
}
