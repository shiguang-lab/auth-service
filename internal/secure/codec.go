package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

type Codec struct {
	aead cipher.AEAD
}

func NewCodec(key []byte) (*Codec, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must contain exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM cipher: %w", err)
	}
	return &Codec{aead: aead}, nil
}

func (c *Codec) Seal(plaintext []byte, context string) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	return c.aead.Seal(nonce, nonce, plaintext, []byte(context)), nil
}

func (c *Codec) Open(ciphertext []byte, context string) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("encrypted value is truncated")
	}
	plaintext, err := c.aead.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], []byte(context))
	if err != nil {
		return nil, errors.New("decrypt value")
	}
	return plaintext, nil
}
