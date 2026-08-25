package platformroleadmin

import (
	"context"
	"slices"
	"sync"
	"time"
)

// MemoryCommandJournal is for unit tests and explicit local fixtures only.
// It has the same CAS semantics as Redis but is not durable across restarts.
type MemoryCommandJournal struct {
	mu       sync.Mutex
	commands map[string]memoryCommand
}

type memoryCommand struct {
	command   RoleCommand
	expiresAt time.Time
}

func NewMemoryCommandJournal() *MemoryCommandJournal {
	return &MemoryCommandJournal{commands: make(map[string]memoryCommand)}
}

func (j *MemoryCommandJournal) CreatePending(_ context.Context, command RoleCommand, ttl time.Duration) (RoleCommand, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.prune(command.UpdatedAt)
	if existing, ok := j.commands[command.OperationID]; ok {
		if existing.command.PayloadFingerprint != command.PayloadFingerprint {
			return RoleCommand{}, false, ErrIdempotencyConflict
		}
		return cloneCommand(existing.command), false, nil
	}
	j.commands[command.OperationID] = memoryCommand{command: cloneCommand(command), expiresAt: command.UpdatedAt.Add(ttl)}
	return cloneCommand(command), true, nil
}

func (j *MemoryCommandJournal) Get(_ context.Context, operationID string) (RoleCommand, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	value, ok := j.commands[operationID]
	if !ok {
		return RoleCommand{}, ErrCommandNotFound
	}
	return cloneCommand(value.command), nil
}

func (j *MemoryCommandJournal) ClaimRetry(_ context.Context, operationID string, now time.Time, lease time.Duration) (RoleCommand, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	value, ok := j.commands[operationID]
	if !ok {
		return RoleCommand{}, ErrCommandNotFound
	}
	command := value.command
	if command.Status == CommandSucceeded {
		return command, ErrCommandConflict
	}
	if command.Status == CommandPending && command.LeaseUntil.After(now) {
		return RoleCommand{}, ErrChangeInProgress
	}
	if command.Status != CommandPending && command.Status != CommandReconcileRequired && command.Status != CommandFailed {
		return RoleCommand{}, ErrCommandConflict
	}
	command.Status = CommandPending
	command.LeaseUntil = now.Add(lease)
	command.UpdatedAt = now
	command.Attempts++
	command.ErrorCode = ""
	command.Version++
	value.command = command
	j.commands[operationID] = value
	return cloneCommand(command), nil
}

func (j *MemoryCommandJournal) MarkSucceeded(_ context.Context, operationID string, version int64, roles []string, now time.Time) (RoleCommand, error) {
	return j.transition(operationID, version, CommandSucceeded, "", roles, now)
}

func (j *MemoryCommandJournal) MarkFailed(_ context.Context, operationID string, version int64, code string, now time.Time) (RoleCommand, error) {
	return j.transition(operationID, version, CommandFailed, code, nil, now)
}

func (j *MemoryCommandJournal) MarkReconcileRequired(_ context.Context, operationID string, version int64, code string, now time.Time) (RoleCommand, error) {
	return j.transition(operationID, version, CommandReconcileRequired, code, nil, now)
}

func (j *MemoryCommandJournal) List(_ context.Context, filter CommandFilter) ([]RoleCommand, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	limit := filter.Limit
	if limit < 1 || limit > 100 {
		limit = 50
	}
	statuses := filter.Statuses
	if len(statuses) == 0 {
		statuses = []CommandStatus{CommandPending, CommandReconcileRequired}
	}
	result := make([]RoleCommand, 0, limit)
	for _, value := range j.commands {
		if slices.Contains(statuses, value.command.Status) {
			result = append(result, cloneCommand(value.command))
		}
	}
	slices.SortFunc(result, func(left, right RoleCommand) int { return left.RequestedAt.Compare(right.RequestedAt) })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (j *MemoryCommandJournal) transition(operationID string, version int64, status CommandStatus, code string, roles []string, now time.Time) (RoleCommand, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	value, ok := j.commands[operationID]
	if !ok {
		return RoleCommand{}, ErrCommandNotFound
	}
	if value.command.Version != version || value.command.Status != CommandPending {
		return RoleCommand{}, ErrCommandConflict
	}
	value.command.Status = status
	value.command.ErrorCode = code
	value.command.ResultRoles = append([]string(nil), roles...)
	value.command.LeaseUntil = time.Time{}
	value.command.UpdatedAt = now
	value.command.Version++
	j.commands[operationID] = value
	return cloneCommand(value.command), nil
}

func (j *MemoryCommandJournal) prune(now time.Time) {
	for key, value := range j.commands {
		if !value.expiresAt.After(now) {
			delete(j.commands, key)
		}
	}
}

func cloneCommand(value RoleCommand) RoleCommand {
	value.BeforeRoles = append([]string(nil), value.BeforeRoles...)
	value.AfterRoles = append([]string(nil), value.AfterRoles...)
	value.ResultRoles = append([]string(nil), value.ResultRoles...)
	return value
}
