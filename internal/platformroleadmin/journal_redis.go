package platformroleadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/shiguanglab/auth-service/internal/secure"
)

type RedisCommandJournal struct {
	client *redis.Client
	codec  *secure.Codec
	prefix string
}

const commandIndexTTL = 91 * 24 * time.Hour

func NewRedisCommandJournal(options *redis.Options, prefix string, encryptionKey []byte) (*RedisCommandJournal, error) {
	if options == nil {
		return nil, errors.New("redis options are required")
	}
	codec, err := secure.NewCodec(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("initialize IAM command encryption: %w", err)
	}
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = "auth:iam-role-command:"
	}
	return &RedisCommandJournal{client: redis.NewClient(options), codec: codec, prefix: prefix}, nil
}

func (j *RedisCommandJournal) Close() error { return j.client.Close() }

func (j *RedisCommandJournal) Ping(ctx context.Context) error {
	if err := j.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("ping IAM command Redis: %w", err)
	}
	return nil
}

func (j *RedisCommandJournal) CreatePending(ctx context.Context, command RoleCommand, ttl time.Duration) (RoleCommand, bool, error) {
	key := j.commandKey(command.OperationID)
	for range 4 {
		var existing RoleCommand
		created := false
		err := j.client.Watch(ctx, func(tx *redis.Tx) error {
			body, err := tx.Get(ctx, key).Bytes()
			if err == nil {
				existing, err = j.decode(key, body)
				if err != nil {
					return err
				}
				if existing.PayloadFingerprint != command.PayloadFingerprint {
					return ErrIdempotencyConflict
				}
				return nil
			}
			if !errors.Is(err, redis.Nil) {
				return err
			}
			body, err = j.encode(key, command)
			if err != nil {
				return err
			}
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, key, body, ttl)
				pipe.ZAdd(ctx, j.indexKey(command.Status), redis.Z{Score: float64(command.RequestedAt.UnixMilli()), Member: command.OperationID})
				pipe.Expire(ctx, j.indexKey(command.Status), commandIndexTTL)
				return nil
			})
			created = err == nil
			return err
		}, key)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		if err != nil {
			return RoleCommand{}, false, fmt.Errorf("create IAM role command: %w", err)
		}
		if created {
			return cloneCommand(command), true, nil
		}
		return cloneCommand(existing), false, nil
	}
	return RoleCommand{}, false, ErrCommandConflict
}

func (j *RedisCommandJournal) Get(ctx context.Context, operationID string) (RoleCommand, error) {
	key := j.commandKey(operationID)
	body, err := j.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return RoleCommand{}, ErrCommandNotFound
	}
	if err != nil {
		return RoleCommand{}, fmt.Errorf("get IAM role command: %w", err)
	}
	return j.decode(key, body)
}

func (j *RedisCommandJournal) ClaimRetry(ctx context.Context, operationID string, now time.Time, lease time.Duration) (RoleCommand, error) {
	return j.mutate(ctx, operationID, func(command *RoleCommand) error {
		if command.Status == CommandPending && command.LeaseUntil.After(now) {
			return ErrChangeInProgress
		}
		if command.Status != CommandPending && command.Status != CommandReconcileRequired && command.Status != CommandFailed {
			return ErrCommandConflict
		}
		command.Status = CommandPending
		command.LeaseUntil = now.Add(lease)
		command.UpdatedAt = now
		command.Attempts++
		command.ErrorCode = ""
		return nil
	})
}

func (j *RedisCommandJournal) MarkSucceeded(ctx context.Context, operationID string, version int64, roles []string, now time.Time) (RoleCommand, error) {
	return j.finish(ctx, operationID, version, CommandSucceeded, "", roles, now)
}

func (j *RedisCommandJournal) MarkFailed(ctx context.Context, operationID string, version int64, code string, now time.Time) (RoleCommand, error) {
	return j.finish(ctx, operationID, version, CommandFailed, code, nil, now)
}

func (j *RedisCommandJournal) MarkReconcileRequired(ctx context.Context, operationID string, version int64, code string, now time.Time) (RoleCommand, error) {
	return j.finish(ctx, operationID, version, CommandReconcileRequired, code, nil, now)
}

func (j *RedisCommandJournal) List(ctx context.Context, filter CommandFilter) ([]RoleCommand, error) {
	limit := filter.Limit
	if limit < 1 || limit > 100 {
		limit = 50
	}
	statuses := filter.Statuses
	if len(statuses) == 0 {
		statuses = []CommandStatus{CommandPending, CommandReconcileRequired}
	}
	result := make([]RoleCommand, 0, limit)
	seen := make(map[string]struct{})
	for _, status := range statuses {
		ids, err := j.client.ZRange(ctx, j.indexKey(status), 0, int64(limit*2-1)).Result()
		if err != nil {
			return nil, fmt.Errorf("list IAM role command index: %w", err)
		}
		for _, id := range ids {
			if _, exists := seen[id]; exists {
				continue
			}
			command, err := j.Get(ctx, id)
			if errors.Is(err, ErrCommandNotFound) {
				_ = j.client.ZRem(ctx, j.indexKey(status), id).Err()
				continue
			}
			if err != nil {
				return nil, err
			}
			if command.Status == status {
				seen[id] = struct{}{}
				result = append(result, command)
			}
		}
	}
	slices.SortFunc(result, func(left, right RoleCommand) int { return left.RequestedAt.Compare(right.RequestedAt) })
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (j *RedisCommandJournal) finish(ctx context.Context, operationID string, version int64, status CommandStatus, code string, roles []string, now time.Time) (RoleCommand, error) {
	return j.mutate(ctx, operationID, func(command *RoleCommand) error {
		if command.Version != version || command.Status != CommandPending {
			return ErrCommandConflict
		}
		command.Status = status
		command.ErrorCode = code
		command.ResultRoles = append([]string(nil), roles...)
		command.LeaseUntil = time.Time{}
		command.UpdatedAt = now
		return nil
	})
}

func (j *RedisCommandJournal) mutate(ctx context.Context, operationID string, change func(*RoleCommand) error) (RoleCommand, error) {
	key := j.commandKey(operationID)
	for range 4 {
		var updated RoleCommand
		err := j.client.Watch(ctx, func(tx *redis.Tx) error {
			body, err := tx.Get(ctx, key).Bytes()
			if errors.Is(err, redis.Nil) {
				return ErrCommandNotFound
			}
			if err != nil {
				return err
			}
			current, err := j.decode(key, body)
			if err != nil {
				return err
			}
			previousStatus := current.Status
			if err := change(&current); err != nil {
				return err
			}
			current.Version++
			body, err = j.encode(key, current)
			if err != nil {
				return err
			}
			ttl, err := tx.PTTL(ctx, key).Result()
			if err != nil || ttl <= 0 {
				return fmt.Errorf("IAM role command TTL is unavailable")
			}
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, key, body, redis.KeepTTL)
				if previousStatus != current.Status {
					pipe.ZRem(ctx, j.indexKey(previousStatus), operationID)
				}
				pipe.ZAdd(ctx, j.indexKey(current.Status), redis.Z{Score: float64(current.RequestedAt.UnixMilli()), Member: operationID})
				pipe.Expire(ctx, j.indexKey(current.Status), commandIndexTTL)
				return nil
			})
			updated = current
			return err
		}, key)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		if err != nil {
			return RoleCommand{}, err
		}
		return cloneCommand(updated), nil
	}
	return RoleCommand{}, ErrCommandConflict
}

func (j *RedisCommandJournal) encode(key string, command RoleCommand) ([]byte, error) {
	body, err := json.Marshal(command)
	if err != nil {
		return nil, fmt.Errorf("encode IAM role command: %w", err)
	}
	body, err = j.codec.Seal(body, key)
	if err != nil {
		return nil, fmt.Errorf("encrypt IAM role command: %w", err)
	}
	return body, nil
}

func (j *RedisCommandJournal) decode(key string, body []byte) (RoleCommand, error) {
	plaintext, err := j.codec.Open(body, key)
	if err != nil {
		return RoleCommand{}, fmt.Errorf("decrypt IAM role command: %w", err)
	}
	var command RoleCommand
	if err := json.Unmarshal(plaintext, &command); err != nil {
		return RoleCommand{}, fmt.Errorf("decode IAM role command: %w", err)
	}
	return command, nil
}

func (j *RedisCommandJournal) commandKey(operationID string) string {
	return j.prefix + "command:" + operationID
}
func (j *RedisCommandJournal) indexKey(status CommandStatus) string {
	return j.prefix + "status:" + string(status)
}
