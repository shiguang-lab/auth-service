package identity

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

type Subject struct {
	Audience              string
	Subject               string
	SessionID             string
	OrganizationID        string
	Roles                 []string
	Entitlements          []string
	AuthenticationTime    time.Time
	AuthenticationMethods []string
}

type Signer struct {
	privateKey *rsa.PrivateKey
	issuer     string
	keyID      string
	ttl        time.Duration
}

func NewSigner(issuer, keyID, keyFile string, ttl time.Duration) (*Signer, error) {
	var key *rsa.PrivateKey
	var err error
	if keyFile == "" {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = loadPrivateKey(keyFile)
	}
	if err != nil {
		return nil, err
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("validate signing key: %w", err)
	}
	return &Signer{privateKey: key, issuer: issuer, keyID: keyID, ttl: ttl}, nil
}

func (s *Signer) Issue(subject Subject, now time.Time) (string, error) {
	header := map[string]any{
		"alg": "RS256",
		"kid": s.keyID,
		"typ": "sg-identity+jwt",
	}
	jti, err := randomID()
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"iss":          s.issuer,
		"aud":          subject.Audience,
		"sub":          subject.Subject,
		"sid":          subject.SessionID,
		"org_id":       subject.OrganizationID,
		"roles":        subject.Roles,
		"entitlements": subject.Entitlements,
		"auth_time":    subject.AuthenticationTime.Unix(),
		"amr":          subject.AuthenticationMethods,
		"jti":          jti,
		"iat":          now.Unix(),
		"nbf":          now.Add(-5 * time.Second).Unix(),
		"exp":          now.Add(s.ttl).Unix(),
	}
	encodedHeader, err := encodeJSON(header)
	if err != nil {
		return "", err
	}
	encodedClaims, err := encodeJSON(claims)
	if err != nil {
		return "", err
	}
	signingInput := encodedHeader + "." + encodedClaims
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign identity token: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (s *Signer) JWKS() map[string]any {
	public := s.privateKey.PublicKey
	exponent := make([]byte, 4)
	binary.BigEndian.PutUint32(exponent, uint32(public.E))
	exponent = trimLeadingZeros(exponent)
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": s.keyID,
			"n":   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(exponent),
		}},
	}
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, errors.New("signing key is not PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("signing key must be PKCS#1 or PKCS#8 RSA")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not RSA")
	}
	return key, nil
}

func encodeJSON(value any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(body), nil
}

func randomID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func trimLeadingZeros(value []byte) []byte {
	for len(value) > 1 && value[0] == 0 {
		value = value[1:]
	}
	return value
}
