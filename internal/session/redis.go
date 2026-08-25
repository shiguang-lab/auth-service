package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/shiguanglab/auth-service/internal/secure"
)

type RedisStore struct {
	client      *redis.Client
	keyPrefix   string
	absoluteTTL time.Duration
	codec       *secure.Codec
}

func NewRedisStore(options *redis.Options, keyPrefix string, absoluteTTL time.Duration, encryptionKey []byte) (*RedisStore, error) {
	if options == nil {
		return nil, errors.New("redis options are required")
	}
	if absoluteTTL <= 0 {
		return nil, errors.New("absolute session TTL must be positive")
	}
	keyPrefix = strings.TrimSpace(keyPrefix)
	if keyPrefix == "" {
		keyPrefix = "auth:session:"
	}
	codec, err := secure.NewCodec(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("initialize session encryption: %w", err)
	}
	return &RedisStore{
		client:      redis.NewClient(options),
		keyPrefix:   keyPrefix,
		absoluteTTL: absoluteTTL,
		codec:       codec,
	}, nil
}

func (s *RedisStore) Get(ctx context.Context, id string) (Session, error) {
	if id == "" {
		return Session{}, ErrNotFound
	}
	body, err := s.client.Get(ctx, s.key(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("get session from redis: %w", err)
	}
	plaintext, err := s.codec.Open(body, s.key(id))
	if err != nil {
		return Session{}, fmt.Errorf("decrypt redis session: %w", err)
	}
	var value Session
	if err := json.Unmarshal(plaintext, &value); err != nil {
		return Session{}, fmt.Errorf("decode redis session: %w", err)
	}
	return value, nil
}

func (s *RedisStore) Put(ctx context.Context, id string, value Session) error {
	if id == "" {
		return errors.New("session id is required")
	}
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode redis session: %w", err)
	}
	body, err = s.codec.Seal(body, s.key(id))
	if err != nil {
		return fmt.Errorf("encrypt redis session: %w", err)
	}
	if err := s.client.Set(ctx, s.key(id), body, s.absoluteTTL).Err(); err != nil {
		return fmt.Errorf("put session in redis: %w", err)
	}
	return nil
}

func (s *RedisStore) UpdatePlatformRoles(ctx context.Context, id, subject string, roles []string, refreshedAt time.Time) (Session, error) {
	if id == "" || subject == "" {
		return Session{}, ErrNotFound
	}
	key := s.key(id)
	var updated Session
	for range 3 {
		err := s.client.Watch(ctx, func(tx *redis.Tx) error {
			body, err := tx.Get(ctx, key).Bytes()
			if errors.Is(err, redis.Nil) {
				return ErrNotFound
			}
			if err != nil {
				return fmt.Errorf("get session for platform role update: %w", err)
			}
			plaintext, err := s.codec.Open(body, key)
			if err != nil {
				return fmt.Errorf("decrypt session for platform role update: %w", err)
			}
			var value Session
			if err := json.Unmarshal(plaintext, &value); err != nil {
				return fmt.Errorf("decode session for platform role update: %w", err)
			}
			if value.Subject != subject {
				return ErrNotFound
			}
			value.PlatformRoles = append([]string(nil), roles...)
			value.PlatformRolesRefreshedAt = refreshedAt
			plaintext, err = json.Marshal(value)
			if err != nil {
				return fmt.Errorf("encode session platform roles: %w", err)
			}
			body, err = s.codec.Seal(plaintext, key)
			if err != nil {
				return fmt.Errorf("encrypt session platform roles: %w", err)
			}
			if _, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, key, body, redis.KeepTTL)
				return nil
			}); err != nil {
				return err
			}
			updated = value
			return nil
		}, key)
		if errors.Is(err, redis.TxFailedErr) {
			continue
		}
		if err != nil {
			return Session{}, err
		}
		return updated, nil
	}
	return Session{}, errors.New("update platform roles conflicted repeatedly")
}

func (s *RedisStore) Revoke(ctx context.Context, id string, at time.Time) error {
	value, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	value.RevokedAt = at
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode revoked session: %w", err)
	}
	body, err = s.codec.Seal(body, s.key(id))
	if err != nil {
		return fmt.Errorf("encrypt revoked session: %w", err)
	}
	if err := s.client.Set(ctx, s.key(id), body, redis.KeepTTL).Err(); err != nil {
		return fmt.Errorf("revoke redis session: %w", err)
	}
	return nil
}

func (s *RedisStore) Ping(ctx context.Context) error {
	if err := s.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("ping redis: %w", err)
	}
	return nil
}

func (s *RedisStore) Close() error {
	return s.client.Close()
}

func (s *RedisStore) key(id string) string {
	sum := sha256.Sum256([]byte(id))
	return s.keyPrefix + hex.EncodeToString(sum[:])
}
