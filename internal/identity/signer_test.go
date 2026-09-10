package identity

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	signer, err := NewSigner("https://shiguanglab.com", "test-key", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func decodeSegment(t *testing.T, token string, index int) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS, got %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

// The two token classes must never be interchangeable. The resource server
// rejects an assertion whose typ is not "sg-identity+jwt", so an access token
// carrying that typ would silently bypass scope enforcement.
func TestAccessTokenAndIdentityAssertionUseDistinctTypes(t *testing.T) {
	signer := newTestSigner(t)
	now := time.Now()

	assertion, err := signer.Issue(Subject{Audience: "asset-hub-api", Subject: "user-1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	access, err := signer.IssueAccessToken(AccessToken{
		Audience:     "asset-hub-api",
		Subject:      "user-1",
		SessionID:    "sid-1",
		ClientID:     "obsidian-asset-hub",
		Scope:        "documents:read documents:write",
		Entitlements: []string{"asset-hub:access"},
		TTL:          15 * time.Minute,
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	if got := decodeSegment(t, assertion, 0)["typ"]; got != "sg-identity+jwt" {
		t.Fatalf("assertion typ = %v", got)
	}
	if got := decodeSegment(t, access, 0)["typ"]; got != "at+jwt" {
		t.Fatalf("access token typ = %v", got)
	}
}

func TestAccessTokenClaims(t *testing.T) {
	signer := newTestSigner(t)
	now := time.Now()
	token, err := signer.IssueAccessToken(AccessToken{
		Audience:       "asset-hub-api",
		Subject:        "user-1",
		SessionID:      "sid-1",
		ClientID:       "obsidian-asset-hub",
		Scope:          "documents:read",
		DisplayName:    "测试用户",
		OrganizationID: "org-1",
		Roles:          []string{"org:member"},
		Entitlements:   []string{"asset-hub:access"},
		TTL:            15 * time.Minute,
	}, now)
	if err != nil {
		t.Fatal(err)
	}

	claims := decodeSegment(t, token, 1)
	if claims["iss"] != "https://shiguanglab.com" {
		t.Fatalf("iss = %v", claims["iss"])
	}
	if claims["client_id"] != "obsidian-asset-hub" {
		t.Fatalf("client_id = %v", claims["client_id"])
	}
	if claims["scope"] != "documents:read" {
		t.Fatalf("scope = %v", claims["scope"])
	}
	if claims["sid"] != "sid-1" {
		t.Fatalf("sid = %v", claims["sid"])
	}
	exp, ok := claims["exp"].(float64)
	if !ok || int64(exp) != now.Add(15*time.Minute).Unix() {
		t.Fatalf("exp = %v", claims["exp"])
	}
	// The resource server requires nbf to be present and numeric.
	if claims["nbf"] == nil {
		t.Fatal("nbf must be set")
	}
}

// The access token must verify against the published JWKS; a token that cannot
// be verified is indistinguishable from a broken signing path.
func TestAccessTokenVerifiesAgainstPublishedJWKS(t *testing.T) {
	signer := newTestSigner(t)
	token, err := signer.IssueAccessToken(AccessToken{
		Audience: "asset-hub-api",
		Subject:  "user-1",
		TTL:      time.Minute,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.Parse([]byte(token), jwt.WithKeySet(signer.JWKS()))
	if err != nil {
		t.Fatalf("verify against JWKS: %v", err)
	}
	subject, ok := parsed.Subject()
	if !ok || subject != "user-1" {
		t.Fatalf("sub = %q (present=%v)", subject, ok)
	}
}
