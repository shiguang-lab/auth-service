package oauth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Handler exposes the authorization server endpoints. They are mounted outside
// the gateway authentication middleware: a native client cannot present the
// shared gateway token, so the endpoints protect themselves through PKCE,
// strict redirect URI validation and the user's own session cookie.
type Handler struct {
	service *Service
	logger  *slog.Logger
}

func NewHandler(service *Service, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{service: service, logger: logger}
}

// Metadata implements RFC 8414 authorization server metadata discovery.
func (h *Handler) Metadata(response http.ResponseWriter, _ *http.Request) {
	issuer := h.service.Issuer()
	writeJSON(response, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth/authorize",
		"token_endpoint":                        issuer + "/oauth/token",
		"device_authorization_endpoint":         issuer + "/oauth/device/authorize",
		"revocation_endpoint":                   issuer + "/oauth/revoke",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"scopes_supported":                      h.service.Registry().ScopesSupported(),
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}

// DeviceAuthorize starts an RFC 8628 authorization request.
func (h *Handler) DeviceAuthorize(response http.ResponseWriter, request *http.Request) {
	setNoStore(response)
	if err := request.ParseForm(); err != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := h.service.StartDeviceAuthorization(request.Context(), request.PostForm.Get("client_id"), request.PostForm.Get("scope"))
	if err != nil {
		h.respondTokenFailure(response, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *Handler) DeviceVerification(response http.ResponseWriter, request *http.Request) {
	prompt, err := h.service.DevicePrompt(request.Context(), request.URL.Query().Get("user_code"), request.Header.Get("Cookie"))
	if err != nil {
		h.renderError(response, http.StatusBadRequest, "设备验证码无效或已过期，请返回发起连接的应用重新登录。")
		return
	}
	if prompt.Redirect != "" {
		http.Redirect(response, request, prompt.Redirect, http.StatusFound)
		return
	}
	h.renderDevice(response, prompt, "")
}

func (h *Handler) DeviceVerificationSubmit(response http.ResponseWriter, request *http.Request) {
	if request.Header.Get("Origin") != h.service.Issuer() {
		h.renderError(response, http.StatusForbidden, "请求来源无效。")
		return
	}
	if err := request.ParseForm(); err != nil {
		h.renderError(response, http.StatusBadRequest, "请求格式不正确。")
		return
	}
	code := request.PostForm.Get("user_code")
	err := h.service.DecideDevice(request.Context(), code, request.PostForm.Get("decision") == "allow", request.Header.Get("Cookie"))
	if errors.Is(err, ErrNoSession) {
		location := h.service.loginURL + "?" + url.Values{"return_to": {"/oauth/device?user_code=" + url.QueryEscape(code)}}.Encode()
		http.Redirect(response, request, location, http.StatusFound)
		return
	}
	if err != nil {
		h.renderError(response, http.StatusBadRequest, "设备授权已失效，请返回发起连接的应用重新登录。")
		return
	}
	h.renderDevice(response, DevicePrompt{}, "授权处理完成，可以关闭此页面并返回发起连接的应用。")
}

// DeviceContext is the JSON contract consumed by the public Website page.
// Keeping the page outside auth-service lets every first-party app share the
// same branded UI while client validation and session binding stay here.
func (h *Handler) DeviceContext(response http.ResponseWriter, request *http.Request) {
	setNoStore(response)
	prompt, err := h.service.DevicePrompt(request.Context(), request.URL.Query().Get("user_code"), request.Header.Get("Cookie"))
	if err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_or_expired_user_code"})
		return
	}
	if prompt.Redirect != "" {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "login_required", "login_url": prompt.Redirect})
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"user_code":   prompt.UserCode,
		"client_name": prompt.ClientName,
		"scopes":      prompt.Scopes,
	})
}

func (h *Handler) DeviceDecision(response http.ResponseWriter, request *http.Request) {
	setNoStore(response)
	if request.Header.Get("Origin") != h.service.Issuer() {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	if err := request.ParseForm(); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	decision := request.PostForm.Get("decision")
	if decision != "allow" && decision != "deny" {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_decision"})
		return
	}
	err := h.service.DecideDevice(request.Context(), request.PostForm.Get("user_code"), decision == "allow", request.Header.Get("Cookie"))
	if errors.Is(err, ErrNoSession) {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "login_required"})
		return
	}
	if err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_or_expired_user_code"})
		return
	}
	status := "denied"
	if decision == "allow" {
		status = "approved"
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": status})
}

func (h *Handler) WebSessionTicket(response http.ResponseWriter, request *http.Request) {
	setNoStore(response)
	authorization := request.Header.Get("Authorization")
	scheme, token, ok := strings.Cut(authorization, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		writeOAuthError(response, http.StatusUnauthorized, "invalid_token")
		return
	}
	if err := request.ParseForm(); err != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	result, err := h.service.CreateWebSessionTicket(request.Context(), strings.TrimSpace(token), request.PostForm.Get("return_to"))
	if err != nil {
		writeOAuthError(response, http.StatusUnauthorized, "invalid_token")
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *Handler) WebSession(response http.ResponseWriter, request *http.Request) {
	setNoStore(response)
	response.Header().Set("Referrer-Policy", "no-referrer")
	result, err := h.service.ConsumeWebSessionTicket(request.Context(), request.URL.Query().Get("ticket"))
	if err != nil {
		h.renderError(response, http.StatusBadRequest, "登录链接无效或已过期，请返回 Obsidian 重试。")
		return
	}
	http.SetCookie(response, &http.Cookie{Name: h.service.cookieName, Value: result.SessionCredential, Path: "/", Domain: h.service.cookieDomain, MaxAge: int(h.service.absoluteTTL.Seconds()), Secure: strings.HasPrefix(h.service.issuer, "https://"), HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(response, request, result.ReturnTo, http.StatusFound)
}

// Authorize handles GET /oauth/authorize.
func (h *Handler) Authorize(response http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	outcome, err := h.service.Authorize(request.Context(), AuthorizeRequest{
		ResponseType:        query.Get("response_type"),
		ClientID:            query.Get("client_id"),
		RedirectURI:         query.Get("redirect_uri"),
		Scope:               query.Get("scope"),
		State:               query.Get("state"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
		Cookie:              request.Header.Get("Cookie"),
	})
	if err != nil {
		h.respondAuthorizeFailure(response, err)
		return
	}
	if outcome.Redirect != "" {
		http.Redirect(response, request, outcome.Redirect, http.StatusFound)
		return
	}
	h.renderConsent(response, outcome.Consent)
}

// ConsentSubmit handles POST /oauth/authorize, the consent form submission.
func (h *Handler) ConsentSubmit(response http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		h.renderError(response, http.StatusBadRequest, "请求格式不正确。")
		return
	}
	location, err := h.service.Consent(
		request.Context(),
		request.PostForm.Get("consent_id"),
		request.PostForm.Get("decision") == "allow",
		request.Header.Get("Cookie"),
	)
	if err != nil {
		if errors.Is(err, ErrNoSession) || errors.Is(err, ErrPendingNotFound) {
			h.renderError(response, http.StatusBadRequest, "授权请求已失效或登录状态已变更，请重新发起授权。")
			return
		}
		h.logger.Error("oauth consent failed", "error", err)
		h.renderError(response, http.StatusInternalServerError, "服务暂时不可用，请稍后重试。")
		return
	}
	http.Redirect(response, request, location, http.StatusFound)
}

// Token handles POST /oauth/token for the authorization_code and refresh_token
// grants.
func (h *Handler) Token(response http.ResponseWriter, request *http.Request) {
	setNoStore(response)
	if err := request.ParseForm(); err != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	switch request.PostForm.Get("grant_type") {
	case "authorization_code":
		tokens, err := h.service.ExchangeCode(
			request.Context(),
			request.PostForm.Get("code"),
			request.PostForm.Get("client_id"),
			request.PostForm.Get("redirect_uri"),
			request.PostForm.Get("code_verifier"),
		)
		if err != nil {
			h.respondTokenFailure(response, err)
			return
		}
		writeTokenResponse(response, tokens)
	case "refresh_token":
		tokens, err := h.service.Refresh(
			request.Context(),
			request.PostForm.Get("refresh_token"),
			request.PostForm.Get("client_id"),
		)
		if err != nil {
			h.respondTokenFailure(response, err)
			return
		}
		writeTokenResponse(response, tokens)
	case "urn:ietf:params:oauth:grant-type:device_code":
		tokens, err := h.service.ExchangeDevice(request.Context(), request.PostForm.Get("device_code"), request.PostForm.Get("client_id"))
		if err != nil {
			switch {
			case errors.Is(err, ErrAuthorizationPending):
				writeOAuthError(response, http.StatusBadRequest, "authorization_pending")
			case errors.Is(err, ErrAccessDenied):
				writeOAuthError(response, http.StatusBadRequest, "access_denied")
			case errors.Is(err, ErrExpiredToken):
				writeOAuthError(response, http.StatusBadRequest, "expired_token")
			default:
				h.respondTokenFailure(response, err)
			}
			return
		}
		writeTokenResponse(response, tokens)
	default:
		writeOAuthError(response, http.StatusBadRequest, "unsupported_grant_type")
	}
}

// Revoke handles POST /oauth/revoke. An unknown token still yields 200 so the
// endpoint cannot be used to probe for valid tokens.
func (h *Handler) Revoke(response http.ResponseWriter, request *http.Request) {
	setNoStore(response)
	if err := request.ParseForm(); err != nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := h.service.Revoke(request.Context(), request.PostForm.Get("token")); err != nil {
		h.logger.Error("oauth revoke failed", "error", err)
		writeOAuthError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	response.WriteHeader(http.StatusOK)
}

func (h *Handler) respondAuthorizeFailure(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrMissingScope):
		h.renderError(response, http.StatusForbidden, "当前账号没有访问知序资产中心的权限，请联系管理员开通。")
	case errors.Is(err, ErrNoSession):
		h.renderError(response, http.StatusUnauthorized, "登录状态已失效，请重新登录后重试。")
	default:
		h.logger.Warn("oauth authorize rejected", "error", err)
		h.renderError(response, http.StatusBadRequest, "授权请求参数不合法或不被支持。")
	}
}

func (h *Handler) respondTokenFailure(response http.ResponseWriter, err error) {
	if errors.Is(err, ErrInvalidClient) {
		writeOAuthError(response, http.StatusUnauthorized, "invalid_client")
		return
	}
	if errors.Is(err, ErrInvalidGrant) {
		writeOAuthError(response, http.StatusBadRequest, "invalid_grant")
		return
	}
	h.logger.Error("oauth token endpoint failed", "error", err)
	writeOAuthError(response, http.StatusServiceUnavailable, "temporarily_unavailable")
}

func writeTokenResponse(response http.ResponseWriter, tokens TokenResponse) {
	payload := map[string]any{
		"access_token": tokens.AccessToken,
		"token_type":   tokens.TokenType,
		"expires_in":   tokens.ExpiresIn,
		"scope":        tokens.Scope,
	}
	if tokens.RefreshToken != "" {
		payload["refresh_token"] = tokens.RefreshToken
	}
	writeJSON(response, http.StatusOK, payload)
}

func writeOAuthError(response http.ResponseWriter, status int, code string) {
	writeJSON(response, status, map[string]string{"error": code})
}

func setNoStore(response http.ResponseWriter) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
}

func writeJSON(response http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Content-Length", strconv.Itoa(len(body)))
	response.WriteHeader(status)
	_, _ = response.Write(body)
}
