package session

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrNotFound = errors.New("session not found")

type Session struct {
	AssertionSessionID    string
	Subject               string
	OrganizationID        string
	Roles                 []string
	Entitlements          []string
	AuthenticationTime    time.Time
	AuthenticationMethods []string
	CreatedAt             time.Time
	LastSeenAt            time.Time
	RevokedAt             time.Time
}

type Store interface {
	Get(context.Context, string) (Session, error)
	Put(context.Context, string, Session) error
	Revoke(context.Context, string, time.Time) error
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

func clone(value Session) Session {
	value.Roles = append([]string(nil), value.Roles...)
	value.Entitlements = append([]string(nil), value.Entitlements...)
	value.AuthenticationMethods = append([]string(nil), value.AuthenticationMethods...)
	return value
}
