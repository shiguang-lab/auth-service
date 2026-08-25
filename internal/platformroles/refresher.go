// Package platformroles keeps privileged, context-independent roles in browser
// sessions fresh without coupling authorization decisions to every directory
// request.
package platformroles

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/shiguanglab/auth-service/internal/session"
	"github.com/shiguanglab/auth-service/internal/zitadel"
)

const (
	DefaultTTL     = 60 * time.Second
	// ZITADEL authorization search can take around two seconds on the NAS
	// during a cold database/cache path. Keep the refresh bounded, but leave
	// enough headroom so a transient slow lookup does not hide every
	// platform-admin menu from an otherwise valid session.
	DefaultTimeout = 5 * time.Second
)

type Directory interface {
	ListAuthorizations(context.Context, zitadel.AuthorizationFilter) ([]zitadel.Authorization, error)
}

type flight struct {
	done    chan struct{}
	roles   []string
	err     error
	waiters int
}

type Refresher struct {
	store          session.Store
	directory      Directory
	organizationID string
	projectID      string
	ttl            time.Duration
	timeout        time.Duration
	logger         *slog.Logger
	now            func() time.Time

	mu      sync.Mutex
	flights map[string]*flight
}

func New(
	store session.Store,
	directory Directory,
	organizationID, projectID string,
	logger *slog.Logger,
) *Refresher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Refresher{
		store:          store,
		directory:      directory,
		organizationID: organizationID,
		projectID:      projectID,
		ttl:            DefaultTTL,
		timeout:        DefaultTimeout,
		logger:         logger,
		now:            time.Now,
		flights:        make(map[string]*flight),
	}
}

// Refresh returns the current session with platform roles refreshed when their
// cache is stale. Directory failures deliberately produce an empty role set;
// ordinary entitlements remain untouched. The store updates only the role
// fields atomically, preserving concurrent revocation and organization changes.
func (r *Refresher) Refresh(ctx context.Context, sessionID string, current session.Session) (session.Session, error) {
	if r == nil || r.directory == nil || r.store == nil || r.organizationID == "" || r.projectID == "" {
		return current, nil
	}
	now := r.now().UTC()
	if !current.PlatformRolesRefreshedAt.IsZero() && now.Sub(current.PlatformRolesRefreshedAt) < r.ttl {
		return current, nil
	}
	if sessionID == "" || current.Subject == "" {
		return session.Session{}, errors.New("session id and subject are required for platform role refresh")
	}

	roles, directoryErr := r.resolve(ctx, current.Subject)
	if directoryErr != nil {
		roles = nil
		r.logger.Warn("refresh platform roles failed closed", "subject", current.Subject, "error", directoryErr)
	}
	return r.store.UpdatePlatformRoles(ctx, sessionID, current.Subject, roles, now)
}

func (r *Refresher) resolve(ctx context.Context, subject string) ([]string, error) {
	r.mu.Lock()
	if existing := r.flights[subject]; existing != nil {
		existing.waiters++
		r.mu.Unlock()
		select {
		case <-existing.done:
			return append([]string(nil), existing.roles...), existing.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &flight{done: make(chan struct{})}
	r.flights[subject] = call
	r.mu.Unlock()

	lookupContext, cancel := context.WithTimeout(ctx, r.timeout)
	authorizations, err := r.directory.ListAuthorizations(lookupContext, zitadel.AuthorizationFilter{
		UserID:         subject,
		OrganizationID: r.organizationID,
		ProjectID:      r.projectID,
		ActiveOnly:     true,
	})
	cancel()
	roles := make([]string, 0, 4)
	if err == nil {
		for _, authorization := range authorizations {
			roles = appendUnique(roles, authorization.Roles...)
		}
	}

	r.mu.Lock()
	call.roles = roles
	call.err = err
	delete(r.flights, subject)
	close(call.done)
	r.mu.Unlock()
	return append([]string(nil), roles...), err
}

func appendUnique(target []string, values ...string) []string {
	seen := make(map[string]struct{}, len(target)+len(values))
	for _, value := range target {
		seen[value] = struct{}{}
	}
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		target = append(target, value)
	}
	return target
}
