package login

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/shiguanglab/auth-service/internal/secure"
)

var errTransactionNotFound = errors.New("login transaction not found")

type transaction struct {
	State        string    `json:"state"`
	Nonce        string    `json:"nonce"`
	PKCEVerifier string    `json:"pkce_verifier"`
	ReturnTo     string    `json:"return_to"`
	CreatedAt    time.Time `json:"created_at"`
}

type linkTransaction struct {
	State     string    `json:"state"`
	Subject   string    `json:"subject"`
	Provider  string    `json:"provider"`
	ReturnTo  string    `json:"return_to"`
	CreatedAt time.Time `json:"created_at"`
}

type loginAttempt struct {
	CSRFToken string    `json:"csrf_token"`
	ReturnTo  string    `json:"return_to"`
	CreatedAt time.Time `json:"created_at"`
}

type transactionStore struct {
	client *redis.Client
	codec  *secure.Codec
	prefix string
	ttl    time.Duration
}

func newTransactionStore(options *redis.Options, prefix string, key []byte) (*transactionStore, error) {
	codec, err := secure.NewCodec(key)
	if err != nil {
		return nil, err
	}
	return &transactionStore{
		client: redis.NewClient(options),
		codec:  codec,
		prefix: prefix,
		ttl:    10 * time.Minute,
	}, nil
}

func (s *transactionStore) putTransaction(ctx context.Context, value transaction) error {
	return s.put(ctx, "tx:", value.State, value, s.ttl)
}

func (s *transactionStore) getTransaction(ctx context.Context, state string) (transaction, error) {
	var value transaction
	if err := s.get(ctx, "tx:", state, &value); err != nil {
		return transaction{}, err
	}
	return value, nil
}

func (s *transactionStore) deleteTransaction(ctx context.Context, state string) error {
	return s.client.Del(ctx, s.key("tx:", state)).Err()
}

func (s *transactionStore) putLinkTransaction(ctx context.Context, value linkTransaction) error {
	return s.put(ctx, "link:", value.State, value, s.ttl)
}

func (s *transactionStore) getLinkTransaction(ctx context.Context, state string) (linkTransaction, error) {
	var value linkTransaction
	if err := s.get(ctx, "link:", state, &value); err != nil {
		return linkTransaction{}, err
	}
	return value, nil
}

func (s *transactionStore) deleteLinkTransaction(ctx context.Context, state string) error {
	return s.client.Del(ctx, s.key("link:", state)).Err()
}

func (s *transactionStore) putAttempt(ctx context.Context, transactionID string, value loginAttempt) error {
	return s.put(ctx, "attempt:", transactionID, value, s.ttl)
}

func (s *transactionStore) takeAttempt(ctx context.Context, transactionID string) (loginAttempt, error) {
	key := s.key("attempt:", transactionID)
	body, err := s.client.GetDel(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return loginAttempt{}, errTransactionNotFound
	}
	if err != nil {
		return loginAttempt{}, err
	}
	plaintext, err := s.codec.Open(body, key)
	if err != nil {
		return loginAttempt{}, err
	}
	var value loginAttempt
	if err := json.Unmarshal(plaintext, &value); err != nil {
		return loginAttempt{}, err
	}
	return value, nil
}

func (s *transactionStore) allowAttempt(ctx context.Context, identity string) (bool, error) {
	key := s.key("rate:", identity)
	count, err := s.client.Incr(ctx, key).Result()
	if err != nil {
		return false, err
	}
	if count == 1 {
		if err := s.client.Expire(ctx, key, time.Minute).Err(); err != nil {
			return false, err
		}
	}
	return count <= 8, nil
}

func (s *transactionStore) ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

func (s *transactionStore) close() error {
	return s.client.Close()
}

func (s *transactionStore) put(ctx context.Context, kind, id string, value any, ttl time.Duration) error {
	key := s.key(kind, id)
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	body, err = s.codec.Seal(body, key)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, key, body, ttl).Err()
}

func (s *transactionStore) get(ctx context.Context, kind, id string, value any) error {
	key := s.key(kind, id)
	body, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return errTransactionNotFound
	}
	if err != nil {
		return err
	}
	plaintext, err := s.codec.Open(body, key)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(plaintext, value); err != nil {
		return fmt.Errorf("decode login transaction: %w", err)
	}
	return nil
}

func (s *transactionStore) key(kind, id string) string {
	sum := sha256.Sum256([]byte(id))
	return s.prefix + kind + hex.EncodeToString(sum[:])
}
