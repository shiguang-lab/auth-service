package oauth

import (
	"strings"
	"testing"
	"time"
)

func testPolicy(t *testing.T, redirectURIs ...string) ClientPolicy {
	t.Helper()
	policy := ClientPolicy{
		ClientID:     "obsidian-asset-hub",
		Name:         "知序资产中心 for Obsidian",
		RedirectURIs: redirectURIs,
		Scopes:       []string{ScopeDocumentsRead, ScopeDocumentsWrite, ScopeOfflineAccess},
		Audience:     "asset-hub-api",
		AccessTTL:    15 * time.Minute,
		RefreshTTL:   30 * 24 * time.Hour,
	}
	return policy
}

func TestRedirectURIAcceptsAnyPortOnLoopback(t *testing.T) {
	registry, err := NewRegistry([]ClientPolicy{testPolicy(t, "http://127.0.0.1/callback", "http://[::1]/callback")})
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := registry.Client("obsidian-asset-hub")

	for _, candidate := range []string{
		"http://127.0.0.1:1/callback",
		"http://127.0.0.1:51234/callback",
		"http://127.0.0.1:65535/callback",
		"http://[::1]:8080/callback",
	} {
		t.Run(candidate, func(t *testing.T) {
			if err := registry.ValidateRedirectURI(policy, candidate); err != nil {
				t.Fatalf("expected %q to be accepted: %v", candidate, err)
			}
		})
	}
}

func TestRedirectURIRejectsNonLoopbackShapes(t *testing.T) {
	registry, err := NewRegistry([]ClientPolicy{testPolicy(t, "http://127.0.0.1/callback", "http://[::1]/callback")})
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := registry.Client("obsidian-asset-hub")

	// Each of these is a distinct way to escape the loopback: a look-alike host
	// that satisfies a naive prefix match, a LAN address, TLS, a different path,
	// an appended query, and a missing port.
	for _, candidate := range []string{
		"http://127.0.0.1.evil.com:8080/callback",
		"http://192.168.1.5:8080/callback",
		"https://127.0.0.1:8080/callback",
		"http://127.0.0.1:8080/other",
		"http://127.0.0.1:8080/callback?redirect=https://evil.com",
		"http://127.0.0.1:8080/callback#fragment",
		"http://user@127.0.0.1:8080/callback",
		"http://127.0.0.1/callback",
		"http://localhost:8080/callback",
		"",
	} {
		t.Run(candidate, func(t *testing.T) {
			if err := registry.ValidateRedirectURI(policy, candidate); err == nil {
				t.Fatalf("expected %q to be rejected", candidate)
			}
		})
	}
}

func TestRedirectURIPinnedPortIsExact(t *testing.T) {
	registry, err := NewRegistry([]ClientPolicy{testPolicy(t, "http://127.0.0.1:27123/callback")})
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := registry.Client("obsidian-asset-hub")

	if err := registry.ValidateRedirectURI(policy, "http://127.0.0.1:27123/callback"); err != nil {
		t.Fatalf("expected the pinned port to match: %v", err)
	}
	if err := registry.ValidateRedirectURI(policy, "http://127.0.0.1:27124/callback"); err == nil {
		t.Fatal("expected a different port to be rejected")
	}
}

func TestRegistryRejectsInvalidConfiguration(t *testing.T) {
	cases := map[string]ClientPolicy{
		"https template": func() ClientPolicy {
			policy := testPolicy(t, "https://127.0.0.1/callback")
			return policy
		}(),
		"non loopback template": func() ClientPolicy {
			policy := testPolicy(t, "http://example.com/callback")
			return policy
		}(),
		"wrong path": func() ClientPolicy {
			policy := testPolicy(t, "http://127.0.0.1/oauth/callback")
			return policy
		}(),
		"missing audience": func() ClientPolicy {
			policy := testPolicy(t, "http://127.0.0.1/callback")
			policy.Audience = ""
			return policy
		}(),
		"no scopes": func() ClientPolicy {
			policy := testPolicy(t, "http://127.0.0.1/callback")
			policy.Scopes = nil
			return policy
		}(),
		"zero access ttl": func() ClientPolicy {
			policy := testPolicy(t, "http://127.0.0.1/callback")
			policy.AccessTTL = 0
			return policy
		}(),
		"no redirect uris": func() ClientPolicy {
			policy := testPolicy(t, "http://127.0.0.1/callback")
			policy.RedirectURIs = nil
			return policy
		}(),
	}
	for name, policy := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRegistry([]ClientPolicy{policy}); err == nil {
				t.Fatal("expected configuration to be rejected")
			}
		})
	}
}

func TestRegistryRejectsDuplicateClientID(t *testing.T) {
	_, err := NewRegistry([]ClientPolicy{
		testPolicy(t, "http://127.0.0.1/callback"),
		testPolicy(t, "http://127.0.0.1/callback"),
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected a duplicate client error, got %v", err)
	}
}

func TestScopeSubset(t *testing.T) {
	allowed := []string{ScopeDocumentsRead, ScopeDocumentsWrite, ScopeOfflineAccess}
	if !subsetOf([]string{ScopeDocumentsRead}, allowed) {
		t.Fatal("expected a subset to be accepted")
	}
	if subsetOf([]string{ScopeDocumentsRead, "documents:admin"}, allowed) {
		t.Fatal("expected an unknown scope to be rejected")
	}
	if !subsetOf(nil, allowed) {
		t.Fatal("expected an empty request to be a subset")
	}
}
