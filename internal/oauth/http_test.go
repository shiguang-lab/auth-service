package oauth

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newTestHandler(t *testing.T) (*Handler, *harness) {
	t.Helper()
	h := newHarness(t)
	return NewHandler(h.service, slog.New(slog.NewTextHandler(io.Discard, nil))), h
}

func TestMetadataDocumentAdvertisesOnlySupportedCapabilities(t *testing.T) {
	handler, _ := newTestHandler(t)
	response := httptest.NewRecorder()
	handler.Metadata(response, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["issuer"] != "https://shiguanglab.com" {
		t.Fatalf("issuer = %v", body["issuer"])
	}
	if body["authorization_endpoint"] != "https://shiguanglab.com/oauth/authorize" {
		t.Fatalf("authorization_endpoint = %v", body["authorization_endpoint"])
	}
	if body["token_endpoint"] != "https://shiguanglab.com/oauth/token" {
		t.Fatalf("token_endpoint = %v", body["token_endpoint"])
	}
	methods, _ := body["code_challenge_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Fatalf("only S256 may be advertised, got %v", body["code_challenge_methods_supported"])
	}
	auth, _ := body["token_endpoint_auth_methods_supported"].([]any)
	if len(auth) != 1 || auth[0] != "none" {
		t.Fatalf("public clients must advertise the none auth method, got %v", body["token_endpoint_auth_methods_supported"])
	}
}

// An invalid redirect_uri must never be echoed back as a redirect, otherwise the
// authorization endpoint becomes an open redirector.
func TestAuthorizeRendersErrorInsteadOfRedirecting(t *testing.T) {
	handler, h := newTestHandler(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	_, challenge := pkcePair(t)

	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {"http://evil.com:8080/callback"},
		"scope":                 {"documents:read"},
		"state":                 {testState},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	request := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil)
	request.Header.Set("Cookie", cookieFor("sess-1"))
	response := httptest.NewRecorder()
	handler.Authorize(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	if location := response.Header().Get("Location"); location != "" {
		t.Fatalf("must not redirect, got Location %q", location)
	}
	if !strings.Contains(response.Body.String(), "授权请求参数不合法") {
		t.Fatalf("unexpected body %q", response.Body.String())
	}
}

func TestAuthorizeRedirectsToLoginWhenUnauthenticated(t *testing.T) {
	handler, _ := newTestHandler(t)
	_, challenge := pkcePair(t)

	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirect},
		"scope":                 {"documents:read"},
		"state":                 {testState},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	request := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil)
	response := httptest.NewRecorder()
	handler.Authorize(response, request)

	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", response.Code)
	}
	if !strings.HasPrefix(response.Header().Get("Location"), "https://shiguanglab.com/login?") {
		t.Fatalf("location = %q", response.Header().Get("Location"))
	}
}

func TestConsentPageRendersClientAndScopes(t *testing.T) {
	handler, h := newTestHandler(t)
	h.seedSession(t, "sess-1", testSubject, []string{testEntitle})
	_, challenge := pkcePair(t)

	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirect},
		"scope":                 {"documents:read offline_access"},
		"state":                 {testState},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	request := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+query.Encode(), nil)
	request.Header.Set("Cookie", cookieFor("sess-1"))
	response := httptest.NewRecorder()
	handler.Authorize(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, expected := range []string{"知序资产中心 for Obsidian", "读取你的文档中心内容", "长期访问", "consent_id"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("consent page is missing %q", expected)
		}
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("the consent page must not be cached")
	}
}

func TestTokenEndpointCollapsesFailures(t *testing.T) {
	handler, _ := newTestHandler(t)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"never-issued"},
		"client_id":     {testClientID},
		"redirect_uri":  {testRedirect},
		"code_verifier": {strings.Repeat("x", 50)},
	}
	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.Token(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "invalid_grant" {
		t.Fatalf("error = %q", body["error"])
	}
	if len(body) != 1 {
		t.Fatalf("the response must not disclose which check failed: %v", body)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token responses must not be cached")
	}
}

func TestTokenEndpointRejectsUnknownGrantType(t *testing.T) {
	handler, _ := newTestHandler(t)
	form := url.Values{"grant_type": {"password"}}
	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.Token(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "unsupported_grant_type" {
		t.Fatalf("error = %q", body["error"])
	}
}

func TestWebsiteDeviceContextAndDecisionContract(t *testing.T) {
	handler, h := newTestHandler(t)
	h.seedSession(t, "sess-website", testSubject, []string{testEntitle})
	started, err := h.service.StartDeviceAuthorization(t.Context(), testClientID, "documents:read offline_access")
	if err != nil {
		t.Fatal(err)
	}

	contextRequest := httptest.NewRequest(http.MethodGet, "/oauth/device/context?"+url.Values{"user_code": {started.UserCode}}.Encode(), nil)
	contextRequest.Header.Set("Cookie", cookieFor("sess-website"))
	contextResponse := httptest.NewRecorder()
	handler.DeviceContext(contextResponse, contextRequest)
	if contextResponse.Code != http.StatusOK {
		t.Fatalf("context status = %d body=%s", contextResponse.Code, contextResponse.Body.String())
	}
	var contextBody struct {
		UserCode   string        `json:"user_code"`
		ClientName string        `json:"client_name"`
		Scopes     []ScopePrompt `json:"scopes"`
	}
	if err := json.Unmarshal(contextResponse.Body.Bytes(), &contextBody); err != nil {
		t.Fatal(err)
	}
	if contextBody.UserCode != started.UserCode || contextBody.ClientName != "知序资产中心 for Obsidian" || len(contextBody.Scopes) != 2 {
		t.Fatalf("context body = %#v", contextBody)
	}

	form := url.Values{"user_code": {started.UserCode}, "decision": {"allow"}}
	decisionRequest := httptest.NewRequest(http.MethodPost, "/oauth/device/decision", strings.NewReader(form.Encode()))
	decisionRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	decisionRequest.Header.Set("Cookie", cookieFor("sess-website"))
	decisionRequest.Header.Set("Origin", "https://shiguanglab.com")
	decisionResponse := httptest.NewRecorder()
	handler.DeviceDecision(decisionResponse, decisionRequest)
	if decisionResponse.Code != http.StatusOK || !strings.Contains(decisionResponse.Body.String(), `"status":"approved"`) {
		t.Fatalf("decision status = %d body=%s", decisionResponse.Code, decisionResponse.Body.String())
	}
	if _, err := h.service.ExchangeDevice(t.Context(), started.DeviceCode, testClientID); err != nil {
		t.Fatalf("approved device grant cannot be exchanged: %v", err)
	}
}

func TestWebsiteDeviceDecisionRejectsCrossSiteRequest(t *testing.T) {
	handler, _ := newTestHandler(t)
	request := httptest.NewRequest(http.MethodPost, "/oauth/device/decision", strings.NewReader("user_code=ABCD-EFGH&decision=allow"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://example.com")
	response := httptest.NewRecorder()
	handler.DeviceDecision(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"error":"invalid_origin"`) {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
}

// RFC 7009: an unknown token still returns 200 so the endpoint cannot be used
// to probe for valid tokens.
func TestRevokeIsIdempotentForUnknownTokens(t *testing.T) {
	handler, _ := newTestHandler(t)
	form := url.Values{"token": {"nope"}}
	request := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.Revoke(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
}

func TestConsentSubmitRejectsStaleForm(t *testing.T) {
	handler, _ := newTestHandler(t)
	form := url.Values{"consent_id": {"stale"}, "decision": {"allow"}}
	request := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ConsentSubmit(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}
