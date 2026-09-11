package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore keeps the authorization code flow artifacts in Redis so several
// replicas share one view of pending codes, consents and refresh chains.
type RedisStore struct {
	client    *redis.Client
	keyPrefix string
}

func NewRedisStore(options *redis.Options, keyPrefix string) (*RedisStore, error) {
	if options == nil {
		return nil, errors.New("redis options are required")
	}
	keyPrefix = strings.TrimSpace(keyPrefix)
	if keyPrefix == "" {
		keyPrefix = "auth:oauth:"
	}
	if !strings.HasSuffix(keyPrefix, ":") {
		return nil, errors.New("oauth redis key prefix must end with a colon")
	}
	return &RedisStore{client: redis.NewClient(options), keyPrefix: keyPrefix}, nil
}

func (s *RedisStore) PutCode(ctx context.Context, code string, value AuthorizationCode, ttl time.Duration) error {
	if strings.TrimSpace(code) == "" {
		return errors.New("authorization code is required")
	}
	return s.put(ctx, s.codeKey(code), value, ttl)
}

func (s *RedisStore) TakeCode(ctx context.Context, code string) (AuthorizationCode, error) {
	var value AuthorizationCode
	if err := s.take(ctx, s.codeKey(code), &value); err != nil {
		if errors.Is(err, redis.Nil) {
			return AuthorizationCode{}, ErrCodeNotFound
		}
		return AuthorizationCode{}, err
	}
	return value, nil
}

func (s *RedisStore) PutPending(ctx context.Context, id string, value PendingAuthorization, ttl time.Duration) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("pending authorization id is required")
	}
	return s.put(ctx, s.pendingKey(id), value, ttl)
}

func (s *RedisStore) Pending(ctx context.Context, id string) (PendingAuthorization, error) {
	raw, err := s.client.Get(ctx, s.pendingKey(id)).Result()
	if errors.Is(err, redis.Nil) {
		return PendingAuthorization{}, ErrPendingNotFound
	}
	if err != nil {
		return PendingAuthorization{}, fmt.Errorf("load pending authorization: %w", err)
	}
	var value PendingAuthorization
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return PendingAuthorization{}, fmt.Errorf("decode pending authorization: %w", err)
	}
	return value, nil
}

func (s *RedisStore) TakePending(ctx context.Context, id string) (PendingAuthorization, error) {
	var value PendingAuthorization
	if err := s.take(ctx, s.pendingKey(id), &value); err != nil {
		if errors.Is(err, redis.Nil) {
			return PendingAuthorization{}, ErrPendingNotFound
		}
		return PendingAuthorization{}, err
	}
	return value, nil
}

func (s *RedisStore) PutDevice(ctx context.Context, value DeviceAuthorization, ttl time.Duration) error {
	if value.DeviceCode == "" || value.UserCode == "" {
		return errors.New("device and user codes are required")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	pipe := s.client.TxPipeline()
	pipe.Set(ctx, s.deviceKey(value.DeviceCode), encoded, ttl)
	pipe.Set(ctx, s.deviceUserKey(value.UserCode), value.DeviceCode, ttl)
	_, err = pipe.Exec(ctx)
	return err
}

func (s *RedisStore) Device(ctx context.Context, code string) (DeviceAuthorization, error) {
	var value DeviceAuthorization
	raw, err := s.client.Get(ctx, s.deviceKey(code)).Result()
	if errors.Is(err, redis.Nil) {
		return value, ErrDeviceNotFound
	}
	if err != nil {
		return value, err
	}
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return value, err
	}
	return value, nil
}

func (s *RedisStore) DeviceByUserCode(ctx context.Context, userCode string) (DeviceAuthorization, error) {
	code, err := s.client.Get(ctx, s.deviceUserKey(userCode)).Result()
	if errors.Is(err, redis.Nil) {
		return DeviceAuthorization{}, ErrDeviceNotFound
	}
	if err != nil {
		return DeviceAuthorization{}, err
	}
	return s.Device(ctx, code)
}

func (s *RedisStore) UpdateDevice(ctx context.Context, value DeviceAuthorization) error {
	key := s.deviceKey(value.DeviceCode)
	err := s.client.Watch(ctx, func(tx *redis.Tx) error {
		raw, err := tx.Get(ctx, key).Result()
		if errors.Is(err, redis.Nil) {
			return ErrDeviceNotFound
		}
		if err != nil {
			return err
		}
		var current DeviceAuthorization
		if err := json.Unmarshal([]byte(raw), &current); err != nil {
			return err
		}
		if current.Approved || current.Denied {
			return ErrInvalidGrant
		}
		ttl, err := tx.PTTL(ctx, key).Result()
		if err != nil || ttl <= 0 {
			return ErrDeviceNotFound
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, key, encoded, ttl)
			return nil
		})
		return err
	}, key)
	if errors.Is(err, redis.TxFailedErr) {
		return ErrInvalidGrant
	}
	return err
}

func (s *RedisStore) TakeDevice(ctx context.Context, code string) (DeviceAuthorization, error) {
	var value DeviceAuthorization
	if err := s.take(ctx, s.deviceKey(code), &value); err != nil {
		if errors.Is(err, redis.Nil) {
			return value, ErrDeviceNotFound
		}
		return value, err
	}
	_ = s.client.Del(ctx, s.deviceUserKey(value.UserCode)).Err()
	return value, nil
}

func (s *RedisStore) PutAccessBinding(ctx context.Context, hash string, value SessionBinding, ttl time.Duration) error {
	return s.put(ctx, s.bindingKey(hash), value, ttl)
}
func (s *RedisStore) AccessBinding(ctx context.Context, hash string) (SessionBinding, error) {
	var value SessionBinding
	raw, err := s.client.Get(ctx, s.bindingKey(hash)).Result()
	if errors.Is(err, redis.Nil) {
		return value, ErrInvalidGrant
	}
	if err != nil {
		return value, err
	}
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return value, err
	}
	return value, nil
}
func (s *RedisStore) PutWebTicket(ctx context.Context, ticket string, value WebSessionTicket, ttl time.Duration) error {
	return s.put(ctx, s.ticketKey(ticket), value, ttl)
}
func (s *RedisStore) TakeWebTicket(ctx context.Context, ticket string) (WebSessionTicket, error) {
	var value WebSessionTicket
	if err := s.take(ctx, s.ticketKey(ticket), &value); err != nil {
		if errors.Is(err, redis.Nil) {
			return value, ErrInvalidGrant
		}
		return value, err
	}
	return value, nil
}

func (s *RedisStore) PutRefresh(ctx context.Context, value RefreshToken, ttl time.Duration) error {
	if strings.TrimSpace(value.TokenHash) == "" {
		return errors.New("refresh token hash is required")
	}
	if err := s.put(ctx, s.refreshKey(value.TokenHash), value, ttl); err != nil {
		return err
	}
	familyKey := s.familyKey(value.FamilyID)
	pipe := s.client.TxPipeline()
	pipe.SAdd(ctx, familyKey, value.TokenHash)
	pipe.Expire(ctx, familyKey, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("index refresh token family: %w", err)
	}
	return nil
}

// ConsumeRefresh redeems a refresh token exactly once. The single-use marker is
// written with SET NX, so two concurrent redemptions cannot both succeed: the
// loser is treated as a replay and the family is destroyed.
func (s *RedisStore) ConsumeRefresh(ctx context.Context, tokenHash string, now time.Time) (RefreshToken, error) {
	raw, err := s.client.Get(ctx, s.refreshKey(tokenHash)).Result()
	if errors.Is(err, redis.Nil) {
		return RefreshToken{}, ErrRefreshInvalid
	}
	if err != nil {
		return RefreshToken{}, fmt.Errorf("load refresh token: %w", err)
	}
	var value RefreshToken
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return RefreshToken{}, fmt.Errorf("decode refresh token: %w", err)
	}
	if !value.UsedAt.IsZero() {
		if err := s.RevokeFamily(ctx, value.FamilyID); err != nil {
			return RefreshToken{}, err
		}
		return RefreshToken{}, ErrRefreshReused
	}
	ttl, err := s.client.TTL(ctx, s.refreshKey(tokenHash)).Result()
	if err != nil {
		return RefreshToken{}, fmt.Errorf("read refresh token ttl: %w", err)
	}
	if ttl <= 0 {
		return RefreshToken{}, ErrRefreshInvalid
	}
	fresh, err := s.client.SetNX(ctx, s.usedKey(tokenHash), "1", ttl).Result()
	if err != nil {
		return RefreshToken{}, fmt.Errorf("claim refresh token: %w", err)
	}
	if !fresh {
		if err := s.RevokeFamily(ctx, value.FamilyID); err != nil {
			return RefreshToken{}, err
		}
		return RefreshToken{}, ErrRefreshReused
	}
	value.UsedAt = now
	return value, nil
}

func (s *RedisStore) RevokeRefresh(ctx context.Context, tokenHash string) error {
	raw, err := s.client.Get(ctx, s.refreshKey(tokenHash)).Result()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load refresh token: %w", err)
	}
	var value RefreshToken
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return fmt.Errorf("decode refresh token: %w", err)
	}
	return s.RevokeFamily(ctx, value.FamilyID)
}

func (s *RedisStore) RevokeFamily(ctx context.Context, familyID string) error {
	if strings.TrimSpace(familyID) == "" {
		return nil
	}
	familyKey := s.familyKey(familyID)
	members, err := s.client.SMembers(ctx, familyKey).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("read refresh token family: %w", err)
	}
	keys := make([]string, 0, len(members)*2+1)
	for _, tokenHash := range members {
		keys = append(keys, s.refreshKey(tokenHash), s.usedKey(tokenHash))
	}
	keys = append(keys, familyKey)
	if err := s.client.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("revoke refresh token family: %w", err)
	}
	return nil
}

func (s *RedisStore) Close() error { return s.client.Close() }

func (s *RedisStore) put(ctx context.Context, key string, value any, ttl time.Duration) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", key, err)
	}
	if err := s.client.Set(ctx, key, encoded, ttl).Err(); err != nil {
		return fmt.Errorf("store %s: %w", key, err)
	}
	return nil
}

// take atomically reads and deletes a key so a code or consent decision can
// never be replayed.
func (s *RedisStore) take(ctx context.Context, key string, target any) error {
	raw, err := s.client.GetDel(ctx, key).Result()
	if err != nil {
		return err
	}
	if err := json.Unmarshal([]byte(raw), target); err != nil {
		return fmt.Errorf("decode %s: %w", key, err)
	}
	return nil
}

func (s *RedisStore) codeKey(code string) string    { return s.keyPrefix + "code:" + code }
func (s *RedisStore) pendingKey(id string) string   { return s.keyPrefix + "pending:" + id }
func (s *RedisStore) refreshKey(hash string) string { return s.keyPrefix + "refresh:" + hash }
func (s *RedisStore) usedKey(hash string) string    { return s.keyPrefix + "used:" + hash }
func (s *RedisStore) familyKey(id string) string    { return s.keyPrefix + "family:" + id }
func (s *RedisStore) deviceKey(id string) string    { return s.keyPrefix + "device:" + id }
func (s *RedisStore) deviceUserKey(id string) string {
	return s.keyPrefix + "device-user:" + strings.ToUpper(id)
}
func (s *RedisStore) bindingKey(id string) string { return s.keyPrefix + "access-binding:" + id }
func (s *RedisStore) ticketKey(id string) string  { return s.keyPrefix + "web-ticket:" + id }
