package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type Subject struct {
	Audience              string
	Subject               string
	SessionID             string
	DisplayName           string
	OrganizationID        string
	Roles                 []string
	Entitlements          []string
	AuthenticationTime    time.Time
	AuthenticationMethods []string
}

type Signer struct {
	privateKey jwk.Key
	publicKeys jwk.Set
	issuer     string
	ttl        time.Duration
}

func NewSigner(issuer, keyID, keyFile string, ttl time.Duration) (*Signer, error) {
	var raw *rsa.PrivateKey
	var err error
	if keyFile == "" {
		raw, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		raw, err = loadPrivateKey(keyFile)
	}
	if err != nil {
		return nil, err
	}
	if err := raw.Validate(); err != nil {
		return nil, fmt.Errorf("validate signing key: %w", err)
	}

	privateKey, err := jwk.Import(raw)
	if err != nil {
		return nil, fmt.Errorf("create private JWK: %w", err)
	}
	if err := privateKey.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, fmt.Errorf("set JWK key ID: %w", err)
	}
	if err := privateKey.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		return nil, fmt.Errorf("set JWK algorithm: %w", err)
	}
	if err := privateKey.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, fmt.Errorf("set JWK usage: %w", err)
	}

	privateSet := jwk.NewSet()
	if err := privateSet.AddKey(privateKey); err != nil {
		return nil, fmt.Errorf("add private JWK: %w", err)
	}
	publicKeys, err := jwk.PublicSetOf(privateSet)
	if err != nil {
		return nil, fmt.Errorf("derive public JWKS: %w", err)
	}
	return &Signer{
		privateKey: privateKey,
		publicKeys: publicKeys,
		issuer:     issuer,
		ttl:        ttl,
	}, nil
}

func (s *Signer) Issue(subject Subject, now time.Time) (string, error) {
	jti, err := randomID()
	if err != nil {
		return "", err
	}
	token := jwt.New()
	claims := map[string]any{
		jwt.IssuerKey:     s.issuer,
		jwt.AudienceKey:   subject.Audience,
		jwt.SubjectKey:    subject.Subject,
		"sid":             subject.SessionID,
		"name":            subject.DisplayName,
		"org_id":          subject.OrganizationID,
		"roles":           subject.Roles,
		"entitlements":    subject.Entitlements,
		"auth_time":       subject.AuthenticationTime.Unix(),
		"amr":             subject.AuthenticationMethods,
		jwt.JwtIDKey:      jti,
		jwt.IssuedAtKey:   now,
		jwt.NotBeforeKey:  now.Add(-5 * time.Second),
		jwt.ExpirationKey: now.Add(s.ttl),
	}
	for name, value := range claims {
		if err := token.Set(name, value); err != nil {
			return "", fmt.Errorf("set identity claim %q: %w", name, err)
		}
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, "sg-identity+jwt"); err != nil {
		return "", fmt.Errorf("set identity token type: %w", err)
	}
	signed, err := jwt.Sign(
		token,
		jwt.WithKey(jwa.RS256(), s.privateKey, jws.WithProtectedHeaders(headers)),
	)
	if err != nil {
		return "", fmt.Errorf("sign identity token: %w", err)
	}
	return string(signed), nil
}

func (s *Signer) JWKS() jwk.Set {
	return s.publicKeys
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

func randomID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}
