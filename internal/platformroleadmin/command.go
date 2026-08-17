package platformroleadmin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

type CommandStatus string

const (
	CommandPending           CommandStatus = "PENDING"
	CommandSucceeded         CommandStatus = "SUCCEEDED"
	CommandFailed            CommandStatus = "FAILED"
	CommandReconcileRequired CommandStatus = "RECONCILE_REQUIRED"
)

var (
	ErrCommandNotFound     = errors.New("IAM role command not found")
	ErrCommandConflict     = errors.New("IAM role command changed concurrently")
	ErrIdempotencyConflict = errors.New("idempotency key is already bound to another IAM role change")
	ErrChangeInProgress    = errors.New("IAM role change is in progress")
	ErrReconcileRequired   = errors.New("IAM role change requires reconciliation")
	ErrCommandFailed       = errors.New("IAM role change failed")
	ErrManagerRequired     = errors.New("IAM manager role is required")
)

// RoleCommand is a bounded-lifetime operational record. It contains no
// provider token, browser cookie, email address, or unrelated user profile.
type RoleCommand struct {
	OperationID        string        `json:"operationId"`
	PayloadFingerprint string        `json:"payloadFingerprint"`
	Status             CommandStatus `json:"status"`
	ActorSubject       string        `json:"actorSubject"`
	TargetUserID       string        `json:"targetUserId"`
	BeforeRoles        []string      `json:"beforeRoles"`
	AfterRoles         []string      `json:"afterRoles"`
	ManagedRoles       []string      `json:"managedRoles,omitempty"`
	RequestID          string        `json:"requestId,omitempty"`
	RequestedAt        time.Time     `json:"requestedAt"`
	UpdatedAt          time.Time     `json:"updatedAt"`
	LeaseUntil         time.Time     `json:"leaseUntil,omitempty"`
	Attempts           int           `json:"attempts"`
	ErrorCode          string        `json:"errorCode,omitempty"`
	ResultRoles        []string      `json:"resultRoles,omitempty"`
	Version            int64         `json:"version"`
}

type CommandFilter struct {
	Statuses []CommandStatus
	Limit    int
}

type CommandJournal interface {
	CreatePending(context.Context, RoleCommand, time.Duration) (RoleCommand, bool, error)
	Get(context.Context, string) (RoleCommand, error)
	ClaimRetry(context.Context, string, time.Time, time.Duration) (RoleCommand, error)
	MarkSucceeded(context.Context, string, int64, []string, time.Time) (RoleCommand, error)
	MarkFailed(context.Context, string, int64, string, time.Time) (RoleCommand, error)
	MarkReconcileRequired(context.Context, string, int64, string, time.Time) (RoleCommand, error)
	List(context.Context, CommandFilter) ([]RoleCommand, error)
}

// ProviderRoleWriter is the only boundary that may eventually call ZITADEL.
// Desired-state writes must be idempotent and preserve unrelated provider
// roles. No production implementation is included in this phase.
type ProviderRoleWriter interface {
	SetManagedRoles(context.Context, string, []string, []string) (User, error)
}

type ProviderRoleWriterFunc func(context.Context, string, []string, []string) (User, error)

func (f ProviderRoleWriterFunc) SetManagedRoles(ctx context.Context, userID string, roles, managedRoles []string) (User, error) {
	return f(ctx, userID, roles, managedRoles)
}

// ProviderError marks whether a provider failure proves that no mutation took
// place. Unknown outcomes (timeouts, disconnects, malformed responses) require
// reconciliation instead of being reported as a definitive failure.
type ProviderError struct {
	Code       string
	Definitive bool
	Err        error
}

func (e *ProviderError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Code
}

func (e *ProviderError) Unwrap() error { return e.Err }

type DurableChangeExecutor struct {
	journal  CommandJournal
	provider ProviderRoleWriter
	ttl      time.Duration
	lease    time.Duration
	now      func() time.Time
}

func NewDurableChangeExecutor(journal CommandJournal, provider ProviderRoleWriter, ttl, lease time.Duration) (*DurableChangeExecutor, error) {
	if journal == nil || provider == nil {
		return nil, errors.New("command journal and provider writer are required")
	}
	if ttl < 24*time.Hour || ttl > 90*24*time.Hour {
		return nil, errors.New("command journal TTL must be between 24h and 2160h")
	}
	if lease < 5*time.Second || lease > 5*time.Minute {
		return nil, errors.New("command lease must be between 5s and 5m")
	}
	return &DurableChangeExecutor{journal: journal, provider: provider, ttl: ttl, lease: lease, now: time.Now}, nil
}

func (e *DurableChangeExecutor) ApplyRoleChange(ctx context.Context, change RoleChange) (ChangeResult, error) {
	command := commandFromChange(change, e.now().UTC(), e.lease)
	stored, created, err := e.journal.CreatePending(ctx, command, e.ttl)
	if err != nil {
		return ChangeResult{}, err
	}
	if !created {
		return replayResult(stored)
	}
	return e.executeClaimed(ctx, stored)
}

// ApplyPointsRoleChange keeps the original Points-only API source compatible.
// New callers should set ManagedRoles and use ApplyRoleChange.
func (e *DurableChangeExecutor) ApplyPointsRoleChange(ctx context.Context, change RoleChange) (ChangeResult, error) {
	if len(change.ManagedRoles) == 0 {
		change.ManagedRoles = append([]string(nil), ManageableRoles...)
	}
	return e.ApplyRoleChange(ctx, change)
}

// ListRecoverableCommands is service logic for a future internal operations
// API. It is intentionally not mounted on the browser router.
func (e *DurableChangeExecutor) ListRecoverableCommands(ctx context.Context, manager CommandManager, limit int) ([]RoleCommand, error) {
	if !manager.canManage() {
		return nil, ErrManagerRequired
	}
	return e.journal.List(ctx, CommandFilter{Statuses: []CommandStatus{CommandPending, CommandReconcileRequired}, Limit: limit})
}

// RetryCommand claims one command with CAS and a short lease. Concurrent or
// premature retries fail closed and never issue a second provider call.
func (e *DurableChangeExecutor) RetryCommand(ctx context.Context, manager CommandManager, operationID string) (ChangeResult, error) {
	if !manager.canManage() {
		return ChangeResult{}, ErrManagerRequired
	}
	claimed, err := e.journal.ClaimRetry(ctx, operationID, e.now().UTC(), e.lease)
	if err != nil {
		return ChangeResult{}, err
	}
	return e.executeClaimed(ctx, claimed)
}

type CommandManager struct {
	Subject       string
	PlatformRoles []string
}

func NewCommandManager(subject string, platformRoles []string) CommandManager {
	return CommandManager{Subject: strings.TrimSpace(subject), PlatformRoles: append([]string(nil), platformRoles...)}
}

func (m CommandManager) canManage() bool {
	return m.Subject != "" && slices.Contains(m.PlatformRoles, IAMManagerRole)
}

func (e *DurableChangeExecutor) executeClaimed(ctx context.Context, command RoleCommand) (ChangeResult, error) {
	managedRoles := append([]string(nil), command.ManagedRoles...)
	if len(managedRoles) == 0 {
		managedRoles = append([]string(nil), ManageableRoles...)
	}
	user, err := e.provider.SetManagedRoles(ctx, command.TargetUserID, append([]string(nil), command.AfterRoles...), managedRoles)
	now := e.now().UTC()
	if err != nil {
		var providerError *ProviderError
		if errors.As(err, &providerError) && providerError.Definitive {
			if _, journalErr := e.journal.MarkFailed(ctx, command.OperationID, command.Version, safeErrorCode(providerError.Code), now); journalErr != nil {
				return ChangeResult{}, fmt.Errorf("%w: persist definitive provider failure: %v", ErrReconcileRequired, journalErr)
			}
			return ChangeResult{}, fmt.Errorf("%w: %s", ErrCommandFailed, safeErrorCode(providerError.Code))
		}
		if _, journalErr := e.journal.MarkReconcileRequired(ctx, command.OperationID, command.Version, "provider_outcome_unknown", now); journalErr != nil {
			return ChangeResult{}, fmt.Errorf("%w: provider error and journal transition failed: %v", ErrReconcileRequired, journalErr)
		}
		return ChangeResult{}, ErrReconcileRequired
	}
	user.Roles = append([]string(nil), command.AfterRoles...)
	completed, err := e.journal.MarkSucceeded(ctx, command.OperationID, command.Version, command.AfterRoles, now)
	if err != nil {
		// PENDING remains durable when the first result write fails. If Redis is
		// partially available, promote it to the explicit reconcile state.
		_, _ = e.journal.MarkReconcileRequired(ctx, command.OperationID, command.Version, "result_persistence_failed", now)
		return ChangeResult{}, fmt.Errorf("%w: persist provider success: %v", ErrReconcileRequired, err)
	}
	return ChangeResult{User: User{ID: command.TargetUserID, State: "ACTIVE", Roles: append([]string(nil), completed.ResultRoles...)}, OperationID: completed.OperationID, Changed: !slices.Equal(completed.BeforeRoles, completed.AfterRoles)}, nil
}

func commandFromChange(change RoleChange, now time.Time, lease time.Duration) RoleCommand {
	operationHash := sha256.Sum256([]byte(change.ActorSubject + "\x00" + change.IdempotencyKey))
	fingerprintInput := change.TargetUserID + "\x00" + strings.Join(change.AfterRoles, "\x00")
	if len(change.ManagedRoles) > 0 && !sameRoleSet(change.ManagedRoles, ManageableRoles) {
		fingerprintInput = change.TargetUserID + "\x00" + strings.Join(change.ManagedRoles, "\x00") + "\x01" + strings.Join(change.AfterRoles, "\x00")
	}
	fingerprintHash := sha256.Sum256([]byte(fingerprintInput))
	requestedAt := change.RequestedAt.UTC()
	if requestedAt.IsZero() {
		requestedAt = now
	}
	return RoleCommand{
		OperationID: hex.EncodeToString(operationHash[:]), PayloadFingerprint: hex.EncodeToString(fingerprintHash[:]),
		Status: CommandPending, ActorSubject: change.ActorSubject, TargetUserID: change.TargetUserID,
		BeforeRoles: append([]string(nil), change.BeforeRoles...), AfterRoles: append([]string(nil), change.AfterRoles...),
		ManagedRoles: append([]string(nil), change.ManagedRoles...),
		RequestID:    change.RequestID, RequestedAt: requestedAt, UpdatedAt: now, LeaseUntil: now.Add(lease), Attempts: 1, Version: 1,
	}
}

func sameRoleSet(left, right []string) bool {
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	slices.Sort(leftCopy)
	slices.Sort(rightCopy)
	return slices.Equal(leftCopy, rightCopy)
}

func replayResult(command RoleCommand) (ChangeResult, error) {
	switch command.Status {
	case CommandSucceeded:
		if command.ResultRoles == nil {
			return ChangeResult{}, ErrReconcileRequired
		}
		return ChangeResult{User: User{ID: command.TargetUserID, State: "ACTIVE", Roles: append([]string(nil), command.ResultRoles...)}, OperationID: command.OperationID, Replayed: true, Changed: !slices.Equal(command.BeforeRoles, command.AfterRoles)}, nil
	case CommandPending:
		return ChangeResult{}, ErrChangeInProgress
	case CommandReconcileRequired:
		return ChangeResult{}, ErrReconcileRequired
	case CommandFailed:
		return ChangeResult{}, ErrCommandFailed
	default:
		return ChangeResult{}, ErrReconcileRequired
	}
}

func safeErrorCode(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return "provider_rejected"
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '_' {
			continue
		}
		return "provider_rejected"
	}
	return value
}
