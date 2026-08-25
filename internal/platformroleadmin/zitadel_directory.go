package platformroleadmin

import (
	"context"
	"errors"
	"strings"

	"github.com/shiguanglab/auth-service/internal/zitadel"
)

type zitadelDirectoryClient interface {
	SearchUsers(context.Context, string, int) ([]zitadel.User, error)
	SearchUsersByIDs(context.Context, []string) ([]zitadel.User, error)
	ListAuthorizations(context.Context, zitadel.AuthorizationFilter) ([]zitadel.Authorization, error)
}

// ZitadelDirectory exposes only the bounded user fields and platform-project
// roles needed by the IAM editor. It never returns email addresses or provider
// identities.
type ZitadelDirectory struct {
	client         zitadelDirectoryClient
	organizationID string
	projectID      string
}

func NewZitadelDirectory(client zitadelDirectoryClient, organizationID, projectID string) *ZitadelDirectory {
	return &ZitadelDirectory{
		client:         client,
		organizationID: strings.TrimSpace(organizationID),
		projectID:      strings.TrimSpace(projectID),
	}
}

func (d *ZitadelDirectory) SearchUsers(ctx context.Context, query string, limit int) ([]User, error) {
	if !d.configured() {
		return nil, ErrUnavailable
	}
	users, err := d.client.SearchUsers(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	result := make([]User, 0, len(users))
	for _, user := range users {
		mapped, err := d.mapUser(ctx, user)
		if err != nil {
			return nil, err
		}
		if mapped.State == "ACTIVE" {
			result = append(result, mapped)
		}
	}
	return result, nil
}

func (d *ZitadelDirectory) GetUser(ctx context.Context, userID string) (User, error) {
	if !d.configured() {
		return User{}, ErrUnavailable
	}
	users, err := d.client.SearchUsersByIDs(ctx, []string{userID})
	if err != nil {
		return User{}, err
	}
	if len(users) != 1 || users[0].ID != userID {
		return User{}, ErrUnavailable
	}
	return d.mapUser(ctx, users[0])
}

func (d *ZitadelDirectory) configured() bool {
	return d != nil && d.client != nil && d.organizationID != "" && d.projectID != ""
}

func (d *ZitadelDirectory) mapUser(ctx context.Context, source zitadel.User) (User, error) {
	authorizations, err := d.client.ListAuthorizations(ctx, zitadel.AuthorizationFilter{
		UserID:         source.ID,
		OrganizationID: d.organizationID,
		ProjectID:      d.projectID,
		ActiveOnly:     true,
	})
	if err != nil {
		return User{}, err
	}
	roles := make([]string, 0, 8)
	for _, authorization := range authorizations {
		roles = append(roles, authorization.Roles...)
	}
	state := "INACTIVE"
	if source.State == "ACTIVE" || strings.HasSuffix(source.State, "_ACTIVE") {
		state = "ACTIVE"
	}
	if source.ID == "" || source.LoginName == "" {
		return User{}, errors.New("ZITADEL user response is incomplete")
	}
	return User{ID: source.ID, LoginName: source.LoginName, DisplayName: source.DisplayName, State: state, Roles: roles}, nil
}
