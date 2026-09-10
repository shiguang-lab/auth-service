package oauth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// Store errors. Callers translate all of them into a single opaque
// "invalid_grant" response so the token endpoint never becomes an oracle.
var (
	ErrCodeNotFound    = errors.New("authorization code not found")
	ErrPendingNotFound = errors.New("pending authorization not found")
	ErrRefreshInvalid  = errors.New("refresh token is not recognised")
	ErrRefreshReused   = errors.New("refresh token was already redeemed")
)

// AuthorizationCode is a single-use authorization code bound to the exact
// request that produced it.
type AuthorizationCode struct {
	ClientID  string `json:"client_id"`
	Subject   string `json:"subject"`
	SessionID string `json:"session_id"`
	// SessionCredential is the opaque session store key — the value of the
	// session cookie. It is deliberately distinct from SessionID, which is the
	// public assertion id carried in the `sid` claim. Liveness checks must use
	// the credential.
	SessionCredential string    `json:"session_credential"`
	DisplayName       string    `json:"display_name,omitempty"`
	OrganizationID    string    `json:"organization_id,omitempty"`
	Roles             []string  `json:"roles,omitempty"`
	Entitlements      []string  `json:"entitlements,omitempty"`
	Scope             []string  `json:"scope"`
	CodeChallenge     string    `json:"code_challenge"`
	RedirectURI       string    `json:"redirect_uri"`
	CreatedAt         time.Time `json:"created_at"`
}

// PendingAuthorization is an authorization request awaiting the user's consent
// decision. It is addressed by an unguessable ID rendered into the consent form
// and is valid exactly once, which makes the consent POST CSRF-safe without a
// second cookie.
type PendingAuthorization struct {
	ClientID          string    `json:"client_id"`
	Subject           string    `json:"subject"`
	SessionID         string    `json:"session_id"`
	SessionCredential string    `json:"session_credential"`
	RedirectURI       string    `json:"redirect_uri"`
	Scope             []string  `json:"scope"`
	State             string    `json:"state"`
	CodeChallenge     string    `json:"code_challenge"`
	CreatedAt         time.Time `json:"created_at"`
}

// RefreshToken is one link in a rotating refresh token chain.
type RefreshToken struct {
	TokenHash         string    `json:"token_hash"`
	FamilyID          string    `json:"family_id"`
	ClientID          string    `json:"client_id"`
	Subject           string    `json:"subject"`
	SessionID         string    `json:"session_id"`
	SessionCredential string    `json:"session_credential"`
	Scope             []string  `json:"scope"`
	Generation        int       `json:"generation"`
	CreatedAt         time.Time `json:"created_at"`
	UsedAt            time.Time `json:"used_at,omitempty"`
}

// Store holds the short-lived artifacts of the authorization code flow.
//
// ConsumeRefresh must be atomic: it is the single point where replay detection
// happens, and a lost update there would let a stolen token be redeemed twice.
type Store interface {
	PutCode(ctx context.Context, code string, value AuthorizationCode, ttl time.Duration) error
	TakeCode(ctx context.Context, code string) (AuthorizationCode, error)

	PutPending(ctx context.Context, id string, value PendingAuthorization, ttl time.Duration) error
	// Pending reads a pending authorization without consuming it, so a consent
	// submission from the wrong session cannot burn someone else's request.
	Pending(ctx context.Context, id string) (PendingAuthorization, error)
	// TakePending atomically reads and deletes a pending authorization.
	TakePending(ctx context.Context, id string) (PendingAuthorization, error)

	PutRefresh(ctx context.Context, value RefreshToken, ttl time.Duration) error
	ConsumeRefresh(ctx context.Context, tokenHash string, now time.Time) (RefreshToken, error)
	RevokeRefresh(ctx context.Context, tokenHash string) error
	RevokeFamily(ctx context.Context, familyID string) error

	Close() error
}

type codeEntry struct {
	value     AuthorizationCode
	expiresAt time.Time
}

type pendingEntry struct {
	value     PendingAuthorization
	expiresAt time.Time
}

type refreshEntry struct {
	value     RefreshToken
	expiresAt time.Time
}

// MemoryStore is a process-local Store. It is the default when no Redis client
// is configured and is safe for a single replica; multi-replica deployments
// must use RedisStore so codes and refresh chains are shared.
type MemoryStore struct {
	mu          sync.Mutex
	codes       map[string]codeEntry
	pending     map[string]pendingEntry
	refresh     map[string]refreshEntry
	families    map[string]map[string]struct{}
	lastSweep   time.Time
	sweepPeriod time.Duration
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		codes:       make(map[string]codeEntry),
		pending:     make(map[string]pendingEntry),
		refresh:     make(map[string]refreshEntry),
		families:    make(map[string]map[string]struct{}),
		sweepPeriod: time.Minute,
	}
}

func (s *MemoryStore) PutCode(_ context.Context, code string, value AuthorizationCode, ttl time.Duration) error {
	if strings.TrimSpace(code) == "" {
		return errors.New("authorization code is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.sweepLocked(now)
	s.codes[code] = codeEntry{value: cloneCode(value), expiresAt: now.Add(ttl)}
	return nil
}

func (s *MemoryStore) TakeCode(_ context.Context, code string) (AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.codes[code]
	if !ok {
		return AuthorizationCode{}, ErrCodeNotFound
	}
	delete(s.codes, code)
	if !time.Now().Before(entry.expiresAt) {
		return AuthorizationCode{}, ErrCodeNotFound
	}
	return cloneCode(entry.value), nil
}

func (s *MemoryStore) PutPending(_ context.Context, id string, value PendingAuthorization, ttl time.Duration) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("pending authorization id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.sweepLocked(now)
	s.pending[id] = pendingEntry{value: clonePending(value), expiresAt: now.Add(ttl)}
	return nil
}

func (s *MemoryStore) Pending(_ context.Context, id string) (PendingAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.pending[id]
	if !ok {
		return PendingAuthorization{}, ErrPendingNotFound
	}
	if !time.Now().Before(entry.expiresAt) {
		return PendingAuthorization{}, ErrPendingNotFound
	}
	return clonePending(entry.value), nil
}

func (s *MemoryStore) TakePending(_ context.Context, id string) (PendingAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.pending[id]
	if !ok {
		return PendingAuthorization{}, ErrPendingNotFound
	}
	delete(s.pending, id)
	if !time.Now().Before(entry.expiresAt) {
		return PendingAuthorization{}, ErrPendingNotFound
	}
	return clonePending(entry.value), nil
}

func (s *MemoryStore) PutRefresh(_ context.Context, value RefreshToken, ttl time.Duration) error {
	if strings.TrimSpace(value.TokenHash) == "" {
		return errors.New("refresh token hash is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.sweepLocked(now)
	s.refresh[value.TokenHash] = refreshEntry{value: cloneRefresh(value), expiresAt: now.Add(ttl)}
	if s.families[value.FamilyID] == nil {
		s.families[value.FamilyID] = make(map[string]struct{})
	}
	s.families[value.FamilyID][value.TokenHash] = struct{}{}
	return nil
}

func (s *MemoryStore) ConsumeRefresh(_ context.Context, tokenHash string, now time.Time) (RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.refresh[tokenHash]
	if !ok || !now.Before(entry.expiresAt) {
		return RefreshToken{}, ErrRefreshInvalid
	}
	if !entry.value.UsedAt.IsZero() {
		// The token was already redeemed. Assume exfiltration and destroy the
		// whole family, per RFC 6749 §10.4.
		s.revokeFamilyLocked(entry.value.FamilyID)
		return RefreshToken{}, ErrRefreshReused
	}
	entry.value.UsedAt = now
	s.refresh[tokenHash] = entry
	return cloneRefresh(entry.value), nil
}

func (s *MemoryStore) RevokeRefresh(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.refresh[tokenHash]
	if !ok {
		return nil
	}
	s.revokeFamilyLocked(entry.value.FamilyID)
	return nil
}

func (s *MemoryStore) RevokeFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeFamilyLocked(familyID)
	return nil
}

func (s *MemoryStore) Close() error { return nil }

func (s *MemoryStore) revokeFamilyLocked(familyID string) {
	for tokenHash := range s.families[familyID] {
		delete(s.refresh, tokenHash)
	}
	delete(s.families, familyID)
}

// sweepLocked drops expired entries. It runs at most once per sweepPeriod so a
// write-heavy burst does not pay for a full scan every time.
func (s *MemoryStore) sweepLocked(now time.Time) {
	if now.Sub(s.lastSweep) < s.sweepPeriod {
		return
	}
	s.lastSweep = now
	for key, entry := range s.codes {
		if !now.Before(entry.expiresAt) {
			delete(s.codes, key)
		}
	}
	for key, entry := range s.pending {
		if !now.Before(entry.expiresAt) {
			delete(s.pending, key)
		}
	}
	for key, entry := range s.refresh {
		if !now.Before(entry.expiresAt) {
			delete(s.refresh, key)
			if family := s.families[entry.value.FamilyID]; family != nil {
				delete(family, key)
				if len(family) == 0 {
					delete(s.families, entry.value.FamilyID)
				}
			}
		}
	}
}

func cloneCode(value AuthorizationCode) AuthorizationCode {
	value.Roles = append([]string(nil), value.Roles...)
	value.Entitlements = append([]string(nil), value.Entitlements...)
	value.Scope = append([]string(nil), value.Scope...)
	return value
}

func clonePending(value PendingAuthorization) PendingAuthorization {
	value.Scope = append([]string(nil), value.Scope...)
	return value
}

func cloneRefresh(value RefreshToken) RefreshToken {
	value.Scope = append([]string(nil), value.Scope...)
	return value
}
