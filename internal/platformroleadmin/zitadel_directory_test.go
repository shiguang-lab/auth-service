package platformroleadmin

import (
	"context"
	"testing"

	"github.com/shiguanglab/auth-service/internal/zitadel"
)

type fakeZitadelDirectory struct {
	users  []zitadel.User
	roles  map[string][]string
	filter zitadel.AuthorizationFilter
}

func (f *fakeZitadelDirectory) SearchUsers(context.Context, string, int) ([]zitadel.User, error) {
	return append([]zitadel.User(nil), f.users...), nil
}

func (f *fakeZitadelDirectory) SearchUsersByIDs(_ context.Context, ids []string) ([]zitadel.User, error) {
	for _, user := range f.users {
		if len(ids) == 1 && user.ID == ids[0] {
			return []zitadel.User{user}, nil
		}
	}
	return nil, nil
}

func (f *fakeZitadelDirectory) ListAuthorizations(_ context.Context, filter zitadel.AuthorizationFilter) ([]zitadel.Authorization, error) {
	f.filter = filter
	return []zitadel.Authorization{{Roles: append([]string(nil), f.roles[filter.UserID]...)}}, nil
}

func TestZitadelDirectoryReturnsActiveUserAndPlatformRoles(t *testing.T) {
	client := &fakeZitadelDirectory{
		users: []zitadel.User{{ID: "alice", LoginName: "alice@example.com", DisplayName: "Alice", Email: "private@example.com", State: "USER_STATE_ACTIVE"}},
		roles: map[string][]string{"alice": {HuiguangUserRole, IAMManagerRole}},
	}
	directory := NewZitadelDirectory(client, "platform-org", "platform-project")
	users, err := directory.SearchUsers(context.Background(), "alice", 10)
	if err != nil || len(users) != 1 {
		t.Fatalf("users=%#v err=%v", users, err)
	}
	if users[0].ID != "alice" || users[0].State != "ACTIVE" || len(users[0].Roles) != 2 {
		t.Fatalf("user=%#v", users[0])
	}
	if client.filter.OrganizationID != "platform-org" || client.filter.ProjectID != "platform-project" || !client.filter.ActiveOnly {
		t.Fatalf("filter=%#v", client.filter)
	}
}

func TestZitadelDirectoryRejectsMissingAndInactiveUsers(t *testing.T) {
	client := &fakeZitadelDirectory{users: []zitadel.User{{ID: "disabled", LoginName: "disabled@example.com", State: "USER_STATE_INACTIVE"}}, roles: map[string][]string{}}
	directory := NewZitadelDirectory(client, "platform-org", "platform-project")
	users, err := directory.SearchUsers(context.Background(), "disabled", 10)
	if err != nil || len(users) != 0 {
		t.Fatalf("users=%#v err=%v", users, err)
	}
	if _, err := directory.GetUser(context.Background(), "missing"); err == nil {
		t.Fatal("missing user resolved")
	}
}
