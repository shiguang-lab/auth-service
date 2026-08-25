package session

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrNotFound = errors.New("session not found")

const CredentialKindLocalBroker = "local_broker"

type Session struct {
	AssertionSessionID string `json:"assertion_session_id"`
	Subject            string `json:"subject"`
	OrganizationID     string `json:"organization_id,omitempty"`
	OrganizationName   string `json:"organization_name,omitempty"`
	// Roles of the active business-organization context (empty when personal).
	Roles []string `json:"roles,omitempty"`
	// PlatformRoles are context-independent roles granted on the platform
	// project itself (for example system-admin). They survive context
	// switches and are merged into every assertion.
	PlatformRoles            []string  `json:"platform_roles,omitempty"`
	PlatformRolesRefreshedAt time.Time `json:"platform_roles_refreshed_at,omitempty"`
	Entitlements             []string  `json:"entitlements,omitempty"`
	AuthenticationTime       time.Time `json:"authentication_time"`
	AuthenticationMethods    []string  `json:"authentication_methods,omitempty"`
	Email                    string    `json:"email,omitempty"`
	DisplayName              string    `json:"display_name,omitempty"`
	PreferredUsername        string    `json:"preferred_username,omitempty"`
	UpstreamSessionID        string    `json:"upstream_session_id,omitempty"`
	UpstreamSessionToken     string    `json:"upstream_session_token,omitempty"`
	CreatedAt                time.Time `json:"created_at"`
	LastSeenAt               time.Time `json:"last_seen_at"`
	RevokedAt                time.Time `json:"revoked_at,omitempty"`
	CredentialKind           string    `json:"credential_kind,omitempty"`
	CredentialExpiresAt      time.Time `json:"credential_expires_at,omitempty"`
	BrokerProductID          string    `json:"broker_product_id,omitempty"`
}

type Store interface {
	Get(context.Context, string) (Session, error)
	Put(context.Context, string, Session) error
	UpdatePlatformRoles(context.Context, string, string, []string, time.Time) (Session, error)
	Revoke(context.Context, string, time.Time) error
	Ping(context.Context) error
	Close() error
}

type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]Session
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{sessions: make(map[string]Session)}
}

func (s *MemoryStore) Get(_ context.Context, id string) (Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.sessions[id]
	if !ok {
		return Session{}, ErrNotFound
	}
	return clone(value), nil
}

func (s *MemoryStore) Put(_ context.Context, id string, value Session) error {
	if id == "" {
		return errors.New("session id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = clone(value)
	return nil
}

func (s *MemoryStore) UpdatePlatformRoles(_ context.Context, id, subject string, roles []string, refreshedAt time.Time) (Session, error) {
	if id == "" || subject == "" {
		return Session{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.sessions[id]
	if !ok || value.Subject != subject {
		return Session{}, ErrNotFound
	}
	value.PlatformRoles = append([]string(nil), roles...)
	value.PlatformRolesRefreshedAt = refreshedAt
	s.sessions[id] = clone(value)
	return clone(value), nil
}

func (s *MemoryStore) Revoke(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.sessions[id]
	if !ok {
		return ErrNotFound
	}
	value.RevokedAt = at
	s.sessions[id] = value
	return nil
}

func (s *MemoryStore) Ping(context.Context) error {
	return nil
}

func (s *MemoryStore) Close() error {
	return nil
}

func clone(value Session) Session {
	value.Roles = append([]string(nil), value.Roles...)
	value.PlatformRoles = append([]string(nil), value.PlatformRoles...)
	value.Entitlements = append([]string(nil), value.Entitlements...)
	value.AuthenticationMethods = append([]string(nil), value.AuthenticationMethods...)
	return value
}
