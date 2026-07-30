package login

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/redis/go-redis/v9"
	"github.com/shiguanglab/auth-service/internal/config"
	"github.com/shiguanglab/auth-service/internal/session"
	"github.com/shiguanglab/auth-service/internal/zitadel"
	"golang.org/x/oauth2"
)

const csrfCookieName = "__Host-sg_login_csrf"

const zitadelSelectIDPScope = "urn:zitadel:iam:org:idp:id:"

const (
	defaultFeishuAuthorizeURL = "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
	defaultFeishuTokenURL     = "https://accounts.feishu.cn/oauth/v3/token"
	defaultFeishuUserInfoURL  = "https://open.feishu.cn/open-apis/authen/v1/user_info"
)

var (
	usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)
	emailPattern    = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
)

type Service struct {
	cfg          config.Config
	sessions     session.Store
	transactions transactionRepository
	zitadel      zitadelSessionClient
	oidcMu       sync.Mutex
	oidcHTTP     *http.Client
	oauth        oauth2.Config
	verifier     *oidc.IDTokenVerifier
	providerHTTP *http.Client
	feishuURLs   feishuEndpoints
	logger       *slog.Logger
}

type feishuEndpoints struct {
	Authorize string
	Token     string
	UserInfo  string
}

type transactionRepository interface {
	putTransaction(context.Context, transaction) error
	getTransaction(context.Context, string) (transaction, error)
	deleteTransaction(context.Context, string) error
	putLinkTransaction(context.Context, linkTransaction) error
	getLinkTransaction(context.Context, string) (linkTransaction, error)
	deleteLinkTransaction(context.Context, string) error
	putAttempt(context.Context, string, loginAttempt) error
	getAttempt(context.Context, string) (loginAttempt, error)
	takeAttempt(context.Context, string) (loginAttempt, error)
	deleteAttempt(context.Context, string) error
	putFederatedRegistration(context.Context, federatedRegistration) error
	getFederatedRegistration(context.Context, string) (federatedRegistration, error)
	takeFederatedRegistration(context.Context, string) (federatedRegistration, error)
	allowAttempt(context.Context, string) (bool, error)
	ping(context.Context) error
	close() error
}

type zitadelSessionClient interface {
	PasswordSession(context.Context, string, string) (zitadel.Session, error)
	StartEmailOTP(context.Context, string, string) (zitadel.EmailOTPChallenge, error)
	VerifyEmailOTP(context.Context, string, string) (zitadel.Session, error)
	GetUserByID(context.Context, string) (zitadel.User, error)
	DeleteSession(context.Context, string, string) error
	CreateHumanUser(context.Context, string, string, string) (zitadel.CreatedUser, error)
	CreateHumanUserWithIDPLink(context.Context, string, string, string, zitadel.IDPLink) (zitadel.CreatedUser, error)
	ListAuthorizations(context.Context, zitadel.AuthorizationFilter) ([]zitadel.Authorization, error)
	StartIdentityProviderIntent(context.Context, string, string, string) (string, error)
	RetrieveIdentityProviderIntent(context.Context, string, string) (zitadel.IDPInformation, error)
	AddIDPLink(context.Context, string, zitadel.IDPLink) error
	ListIDPLinks(context.Context, string) ([]zitadel.IDPLink, error)
	UpdateHumanUser(context.Context, string, map[string]any) error
	SetUserMetadata(context.Context, string, string, string) error
	GetUserMetadata(context.Context, string, string) (string, error)
}

type identityClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Nonce             string `json:"nonce"`
	AuthTime          int64  `json:"auth_time"`
}

func NewService(_ context.Context, cfg config.Config, sessions session.Store, options *redis.Options, logger *slog.Logger) (*Service, error) {
	if cfg.ZitadelPATFile == "" {
		return nil, nil
	}
	zitadelClient, err := zitadel.NewClient(
		cfg.ZitadelInternalURL,
		cfg.ZitadelIssuer,
		cfg.ZitadelPATFile,
		cfg.ZitadelRegistrationPATFile,
		cfg.ZitadelOrganizationID,
	)
	if err != nil {
		return nil, err
	}
	transactions, err := newTransactionStore(options, "auth:login:", cfg.SessionEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("initialize login transaction store: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		cfg:          cfg,
		sessions:     sessions,
		transactions: transactions,
		zitadel:      zitadelClient,
		providerHTTP: &http.Client{Timeout: 10 * time.Second},
		logger:       logger,
	}, nil
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	return s.transactions.close()
}

func (s *Service) Ping(ctx context.Context) error {
	if s == nil {
		return nil
	}
	return s.transactions.ping(ctx)
}

func (s *Service) Start(response http.ResponseWriter, request *http.Request) {
	provider := strings.TrimSpace(strings.ToLower(request.URL.Query().Get("provider")))
	providerID, ok := s.cfg.OIDCProviderIDs[provider]
	if !ok {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "unsupported_provider"})
		return
	}
	state, err := randomValue(32)
	if err != nil {
		s.serverError(response, err)
		return
	}
	value := transaction{
		State:     state,
		Provider:  provider,
		Federated: true,
		ReturnTo:  s.safeReturnTo(request.URL.Query().Get("return_to")),
		CreatedAt: time.Now().UTC(),
	}
	if err := s.transactions.putTransaction(request.Context(), value); err != nil {
		s.serverError(response, err)
		return
	}
	callback := strings.TrimRight(s.cfg.PublicOrigin, "/") + "/api/auth/oidc/callback?state=" + url.QueryEscape(state)
	authURL, err := s.zitadel.StartIdentityProviderIntent(request.Context(), providerID, callback, callback)
	if err != nil {
		_ = s.transactions.deleteTransaction(request.Context(), state)
		s.serverError(response, err)
		return
	}
	http.Redirect(response, request, authURL, http.StatusFound)
}

// FeishuAuthorize removes generic OAuth parameters that Feishu does not
// support, while preserving ZITADEL's state, callback and optional PKCE data.
func (s *Service) FeishuAuthorize(response http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	if query.Get("client_id") == "" || query.Get("redirect_uri") == "" || query.Get("state") == "" ||
		query.Get("response_type") != "code" {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if !constantEqual(query.Get("client_id"), s.cfg.FeishuAppID) {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_client"})
		return
	}

	target, err := url.Parse(s.feishuEndpoint(s.feishuURLs.Authorize, defaultFeishuAuthorizeURL))
	if err != nil {
		s.serverError(response, err)
		return
	}
	forwarded := make(url.Values)
	for _, key := range []string{
		"client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method",
	} {
		if value := query.Get(key); value != "" {
			forwarded.Set(key, value)
		}
	}
	target.RawQuery = forwarded.Encode()
	response.Header().Set("Cache-Control", "no-store")
	http.Redirect(response, request, target.String(), http.StatusFound)
}

// FeishuToken adapts ZITADEL's standard form-encoded OAuth exchange to
// Feishu's current JSON token endpoint. Client credentials are only forwarded
// to Feishu and are never persisted or logged by Auth Service.
func (s *Service) FeishuToken(response http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(response, request.Body, 32<<10)
	if err := request.ParseForm(); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	clientID, clientSecret := request.Form.Get("client_id"), request.Form.Get("client_secret")
	if basicID, basicSecret, ok := request.BasicAuth(); ok {
		if clientID != "" && !constantEqual(clientID, basicID) || clientSecret != "" && !constantEqual(clientSecret, basicSecret) {
			writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
			return
		}
		if clientID == "" {
			clientID = basicID
		}
		if clientSecret == "" {
			clientSecret = basicSecret
		}
	}
	grantType := request.Form.Get("grant_type")
	if clientID == "" || clientSecret == "" || (grantType != "authorization_code" && grantType != "refresh_token") {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if !constantEqual(clientID, s.cfg.FeishuAppID) {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	payload := map[string]string{
		"grant_type":    grantType,
		"client_id":     clientID,
		"client_secret": clientSecret,
	}
	for _, key := range []string{"code", "redirect_uri", "code_verifier", "refresh_token", "scope"} {
		if value := request.Form.Get(key); value != "" {
			payload[key] = value
		}
	}
	if grantType == "authorization_code" && payload["code"] == "" ||
		grantType == "refresh_token" && payload["refresh_token"] == "" {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		s.serverError(response, err)
		return
	}
	upstreamRequest, err := http.NewRequestWithContext(
		request.Context(),
		http.MethodPost,
		s.feishuEndpoint(s.feishuURLs.Token, defaultFeishuTokenURL),
		bytes.NewReader(body),
	)
	if err != nil {
		s.serverError(response, err)
		return
	}
	upstreamRequest.Header.Set("Content-Type", "application/json; charset=utf-8")
	upstreamRequest.Header.Set("Accept", "application/json")
	upstreamResponse, err := s.feishuHTTPClient().Do(upstreamRequest)
	if err != nil {
		writeJSON(response, http.StatusBadGateway, map[string]string{"error": "provider_unavailable"})
		return
	}
	defer upstreamResponse.Body.Close()
	upstreamBody, err := io.ReadAll(io.LimitReader(upstreamResponse.Body, 1<<20))
	if err != nil || !json.Valid(upstreamBody) {
		writeJSON(response, http.StatusBadGateway, map[string]string{"error": "invalid_provider_response"})
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	response.WriteHeader(upstreamResponse.StatusCode)
	_, _ = response.Write(upstreamBody)
}

// FeishuUserInfo flattens Feishu's {code,data} response into the top-level
// attributes expected by ZITADEL's generic OAuth identity mapper.
func (s *Service) FeishuUserInfo(response http.ResponseWriter, request *http.Request) {
	authorization := strings.TrimSpace(request.Header.Get("Authorization"))
	if len(authorization) < len("Bearer x") || len(authorization) > 8192 ||
		!strings.EqualFold(authorization[:len("Bearer ")], "Bearer ") {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	upstreamRequest, err := http.NewRequestWithContext(
		request.Context(),
		http.MethodGet,
		s.feishuEndpoint(s.feishuURLs.UserInfo, defaultFeishuUserInfoURL),
		nil,
	)
	if err != nil {
		s.serverError(response, err)
		return
	}
	upstreamRequest.Header.Set("Authorization", authorization)
	upstreamRequest.Header.Set("Accept", "application/json")
	upstreamResponse, err := s.feishuHTTPClient().Do(upstreamRequest)
	if err != nil {
		writeJSON(response, http.StatusBadGateway, map[string]string{"error": "provider_unavailable"})
		return
	}
	defer upstreamResponse.Body.Close()
	if upstreamResponse.StatusCode < 200 || upstreamResponse.StatusCode >= 300 {
		writeJSON(response, http.StatusBadGateway, map[string]string{"error": "provider_rejected_token"})
		return
	}
	var upstream struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			Name            string `json:"name"`
			EnglishName     string `json:"en_name"`
			AvatarURL       string `json:"avatar_url"`
			OpenID          string `json:"open_id"`
			UnionID         string `json:"union_id"`
			Email           string `json:"email"`
			EnterpriseEmail string `json:"enterprise_email"`
			TenantKey       string `json:"tenant_key"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(upstreamResponse.Body, 1<<20)).Decode(&upstream); err != nil ||
		upstream.Code != 0 || upstream.Data.OpenID == "" {
		writeJSON(response, http.StatusBadGateway, map[string]string{"error": "invalid_provider_response"})
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	writeJSON(response, http.StatusOK, map[string]any{
		"sub":                upstream.Data.OpenID,
		"open_id":            upstream.Data.OpenID,
		"union_id":           upstream.Data.UnionID,
		"name":               upstream.Data.Name,
		"preferred_username": firstNonEmpty(upstream.Data.EnglishName, upstream.Data.Name, upstream.Data.OpenID),
		"email":              firstNonEmpty(upstream.Data.Email, upstream.Data.EnterpriseEmail),
		"picture":            upstream.Data.AvatarURL,
		"tenant_key":         upstream.Data.TenantKey,
	})
}

func (s *Service) feishuEndpoint(configured, fallback string) string {
	if configured != "" {
		return configured
	}
	return fallback
}

func (s *Service) feishuHTTPClient() *http.Client {
	if s.providerHTTP != nil {
		return s.providerHTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (s *Service) oauthConfigForProvider(oauthConfig oauth2.Config, provider string) (oauth2.Config, error) {
	providerID, ok := s.cfg.OIDCProviderIDs[provider]
	if !ok {
		return oauth2.Config{}, fmt.Errorf("unsupported federated provider %q", provider)
	}
	oauthConfig.Scopes = append(append([]string(nil), oauthConfig.Scopes...), zitadelSelectIDPScope+providerID)
	return oauthConfig, nil
}

func (s *Service) Context(response http.ResponseWriter, request *http.Request) {
	if !s.validOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	var input struct {
		ReturnTo string `json:"returnTo"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	s.createAttempt(response, request, input.ReturnTo)
}

func (s *Service) RegistrationContext(response http.ResponseWriter, request *http.Request) {
	if !s.validOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	s.createAttempt(response, request, "/login")
}

func (s *Service) createAttempt(response http.ResponseWriter, request *http.Request, returnTo string) {
	transactionID, err := randomValue(32)
	if err != nil {
		s.serverError(response, err)
		return
	}
	csrf, err := randomValue(32)
	if err != nil {
		s.serverError(response, err)
		return
	}
	if err := s.transactions.putAttempt(request.Context(), transactionID, loginAttempt{
		CSRFToken: csrf,
		ReturnTo:  s.safeReturnTo(returnTo),
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		s.serverError(response, err)
		return
	}
	http.SetCookie(response, &http.Cookie{
		Name:     csrfCookieName,
		Value:    csrf,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(response, http.StatusOK, map[string]any{
		"transactionId": transactionID,
		"csrfToken":     csrf,
	})
}

func (s *Service) Register(response http.ResponseWriter, request *http.Request) {
	if !s.validOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	var input struct {
		TransactionID string `json:"transactionId"`
		CSRFToken     string `json:"csrfToken"`
		Username      string `json:"username"`
		Email         string `json:"email"`
		Password      string `json:"password"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	csrfCookie, err := request.Cookie(csrfCookieName)
	if err != nil || input.CSRFToken == "" || !constantEqual(csrfCookie.Value, input.CSRFToken) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_csrf"})
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	if input.TransactionID == "" || !usernamePattern.MatchString(input.Username) ||
		!emailPattern.MatchString(input.Email) || len(input.Email) > 200 ||
		len(input.Password) < 8 || len(input.Password) > 200 ||
		!containsLetter(input.Password) || !containsDigit(input.Password) {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_registration"})
		return
	}
	allowed, err := s.transactions.allowAttempt(
		request.Context(),
		"register|"+clientIdentity(request)+"|"+input.Email,
	)
	if err != nil {
		s.serverError(response, err)
		return
	}
	if !allowed {
		writeJSON(response, http.StatusTooManyRequests, map[string]string{"error": "try_again_later"})
		return
	}
	attempt, err := s.transactions.takeAttempt(request.Context(), input.TransactionID)
	if err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "expired_registration"})
		return
	}
	if !constantEqual(attempt.CSRFToken, input.CSRFToken) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_csrf"})
		return
	}
	if _, err := s.zitadel.CreateHumanUser(request.Context(), input.Username, input.Email, input.Password); err != nil {
		var apiError *zitadel.APIError
		if errors.As(err, &apiError) {
			switch apiError.StatusCode {
			case http.StatusConflict:
				writeJSON(response, http.StatusConflict, map[string]string{"error": "account_exists"})
			case http.StatusBadRequest:
				writeJSON(response, http.StatusBadRequest, map[string]string{"error": "registration_rejected"})
			default:
				s.serverError(response, err)
			}
			return
		}
		s.serverError(response, err)
		return
	}
	clearCSRFCookie(response)
	writeJSON(response, http.StatusCreated, map[string]string{"status": "verification_pending"})
}

func (s *Service) FederatedRegistrationContext(response http.ResponseWriter, request *http.Request) {
	if !s.validOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	var input struct {
		TransactionID string `json:"transactionId"`
	}
	if err := decodeJSON(request, &input); err != nil || input.TransactionID == "" || len(input.TransactionID) > 128 {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	pending, err := s.transactions.getFederatedRegistration(request.Context(), input.TransactionID)
	if err != nil || pending.CSRFToken == "" {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "expired_registration"})
		return
	}
	http.SetCookie(response, &http.Cookie{
		Name:     csrfCookieName,
		Value:    pending.CSRFToken,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(response, http.StatusOK, map[string]string{
		"transactionId": pending.TransactionID,
		"csrfToken":     pending.CSRFToken,
		"provider":      pending.Provider,
		"email":         pending.SuggestedEmail,
		"username":      pending.ExternalUserName,
		"displayName":   pending.SuggestedName,
	})
}

func (s *Service) RegisterFederated(response http.ResponseWriter, request *http.Request) {
	if !s.validOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	var input struct {
		TransactionID string `json:"transactionId"`
		CSRFToken     string `json:"csrfToken"`
		Username      string `json:"username"`
		Email         string `json:"email"`
		Password      string `json:"password"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	csrfCookie, err := request.Cookie(csrfCookieName)
	if err != nil || input.CSRFToken == "" || !constantEqual(csrfCookie.Value, input.CSRFToken) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_csrf"})
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	if input.TransactionID == "" || !usernamePattern.MatchString(input.Username) ||
		!emailPattern.MatchString(input.Email) || len(input.Email) > 200 ||
		len(input.Password) < 8 || len(input.Password) > 200 ||
		!containsLetter(input.Password) || !containsDigit(input.Password) {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_registration"})
		return
	}
	allowed, err := s.transactions.allowAttempt(
		request.Context(),
		"federated-register|"+clientIdentity(request)+"|"+input.Email,
	)
	if err != nil {
		s.serverError(response, err)
		return
	}
	if !allowed {
		writeJSON(response, http.StatusTooManyRequests, map[string]string{"error": "try_again_later"})
		return
	}
	pending, err := s.transactions.takeFederatedRegistration(request.Context(), input.TransactionID)
	if err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "expired_registration"})
		return
	}
	if !constantEqual(pending.CSRFToken, input.CSRFToken) ||
		pending.IDPID != s.cfg.OIDCProviderIDs[pending.Provider] || pending.ExternalUserID == "" {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_registration"})
		return
	}
	restorePending := func() {
		if err := s.transactions.putFederatedRegistration(request.Context(), pending); err != nil {
			s.logger.Error("restore federated registration", "error", err)
		}
	}
	created, err := s.zitadel.CreateHumanUserWithIDPLink(
		request.Context(),
		input.Username,
		input.Email,
		input.Password,
		zitadel.IDPLink{IDPID: pending.IDPID, UserID: pending.ExternalUserID, UserName: pending.ExternalUserName},
	)
	if err != nil {
		restorePending()
		var apiError *zitadel.APIError
		if errors.As(err, &apiError) {
			switch apiError.StatusCode {
			case http.StatusConflict:
				writeJSON(response, http.StatusConflict, map[string]string{"error": "account_exists"})
			case http.StatusBadRequest:
				writeJSON(response, http.StatusBadRequest, map[string]string{"error": "registration_rejected"})
			default:
				s.serverError(response, err)
			}
			return
		}
		s.serverError(response, err)
		return
	}
	info := zitadel.IDPInformation{
		UserName:    input.Username,
		Email:       input.Email,
		DisplayName: firstNonEmpty(pending.SuggestedName, input.Username),
	}
	if err := s.createFederatedSession(request.Context(), response, created.ID, info); err != nil {
		s.serverError(response, err)
		return
	}
	clearCSRFCookie(response)
	writeJSON(response, http.StatusCreated, map[string]string{"redirect": pending.ReturnTo})
}

func (s *Service) Password(response http.ResponseWriter, request *http.Request) {
	if !s.validOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	var input struct {
		TransactionID string `json:"transactionId"`
		LoginName     string `json:"loginName"`
		Password      string `json:"password"`
		CSRFToken     string `json:"csrfToken"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	csrfCookie, err := request.Cookie(csrfCookieName)
	if err != nil || input.CSRFToken == "" || !constantEqual(csrfCookie.Value, input.CSRFToken) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_csrf"})
		return
	}
	if input.TransactionID == "" || strings.TrimSpace(input.LoginName) == "" || input.Password == "" ||
		len(input.TransactionID) > 128 || len(input.LoginName) > 320 || len(input.Password) > 1024 {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_credentials"})
		return
	}
	allowed, err := s.transactions.allowAttempt(request.Context(), clientIdentity(request)+"|"+strings.ToLower(input.LoginName))
	if err != nil {
		s.serverError(response, err)
		return
	}
	if !allowed {
		writeJSON(response, http.StatusTooManyRequests, map[string]string{"error": "try_again_later"})
		return
	}
	attempt, err := s.transactions.takeAttempt(request.Context(), input.TransactionID)
	if err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "expired_login"})
		return
	}
	if !constantEqual(attempt.CSRFToken, input.CSRFToken) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_csrf"})
		return
	}

	upstreamSession, err := s.zitadel.PasswordSession(request.Context(), strings.TrimSpace(input.LoginName), input.Password)
	if err != nil {
		s.logger.Warn("ZITADEL password authentication failed", "request_id", request.Header.Get("X-Request-Id"))
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	profile, profileErr := s.zitadel.GetUserByID(request.Context(), upstreamSession.Subject)
	if profileErr != nil {
		s.logger.Warn("load ZITADEL profile after password authentication", "error", profileErr)
	}
	now := time.Now().UTC()
	sessionID, err := randomValue(32)
	if err != nil {
		_ = s.zitadel.DeleteSession(request.Context(), upstreamSession.ID, upstreamSession.Token)
		s.serverError(response, err)
		return
	}
	value := session.Session{
		AssertionSessionID:    sessionID,
		Subject:               upstreamSession.Subject,
		Entitlements:          append([]string(nil), s.cfg.DefaultEntitlements...),
		PlatformRoles:         s.platformRoles(request.Context(), upstreamSession.Subject),
		AuthenticationTime:    now,
		AuthenticationMethods: []string{"pwd"},
		Email:                 profile.Email,
		DisplayName:           firstNonEmpty(profile.DisplayName, upstreamSession.DisplayName, upstreamSession.LoginName),
		PreferredUsername:     firstNonEmpty(profile.LoginName, upstreamSession.LoginName),
		UpstreamSessionID:     upstreamSession.ID,
		UpstreamSessionToken:  upstreamSession.Token,
		CreatedAt:             now,
		LastSeenAt:            now,
	}
	if value.Subject == "" {
		_ = s.zitadel.DeleteSession(request.Context(), upstreamSession.ID, upstreamSession.Token)
		s.serverError(response, errors.New("ZITADEL session does not include a user subject"))
		return
	}
	if err := s.sessions.Put(request.Context(), sessionID, value); err != nil {
		_ = s.zitadel.DeleteSession(request.Context(), upstreamSession.ID, upstreamSession.Token)
		s.serverError(response, err)
		return
	}
	clearCSRFCookie(response)
	s.setSessionCookie(response, sessionID, int(s.cfg.AbsoluteTTL.Seconds()))
	writeJSON(response, http.StatusOK, map[string]string{"redirect": attempt.ReturnTo})
}

func (s *Service) SendEmailCode(response http.ResponseWriter, request *http.Request) {
	if !s.validOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	var input struct {
		TransactionID string `json:"transactionId"`
		Email         string `json:"email"`
		CSRFToken     string `json:"csrfToken"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	csrfCookie, err := request.Cookie(csrfCookieName)
	if err != nil || input.CSRFToken == "" || !constantEqual(csrfCookie.Value, input.CSRFToken) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_csrf"})
		return
	}
	if input.TransactionID == "" || len(input.TransactionID) > 128 ||
		!emailPattern.MatchString(input.Email) || len(input.Email) > 200 {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_email"})
		return
	}
	attempt, err := s.transactions.getAttempt(request.Context(), input.TransactionID)
	if err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "expired_login"})
		return
	}
	if !constantEqual(attempt.CSRFToken, input.CSRFToken) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_csrf"})
		return
	}
	allowed, err := s.transactions.allowAttempt(
		request.Context(),
		"email-code-send|"+clientIdentity(request)+"|"+input.Email,
	)
	if err != nil {
		s.serverError(response, err)
		return
	}
	if !allowed {
		writeJSON(response, http.StatusTooManyRequests, map[string]string{"error": "try_again_later"})
		return
	}
	if attempt.OTPSessionID != "" && attempt.OTPSessionToken != "" {
		_ = s.zitadel.DeleteSession(request.Context(), attempt.OTPSessionID, attempt.OTPSessionToken)
	}

	verificationURL := strings.TrimRight(s.cfg.PublicOrigin, "/") +
		"/api/auth/login/email/callback?transaction_id=" + url.QueryEscape(input.TransactionID) +
		"&code={{.Code}}"
	challenge, challengeErr := s.zitadel.StartEmailOTP(request.Context(), input.Email, verificationURL)
	attempt.Email = input.Email
	attempt.OTPSessionID = ""
	attempt.OTPSessionToken = ""
	attempt.OTPChallengeRequested = true
	if challengeErr == nil {
		attempt.OTPSessionID = challenge.SessionID
		attempt.OTPSessionToken = challenge.SessionToken
	} else {
		var apiError *zitadel.APIError
		if !errors.As(challengeErr, &apiError) || apiError.StatusCode < 400 || apiError.StatusCode >= 500 {
			s.logger.Warn("start ZITADEL email OTP failed", "error", challengeErr, "request_id", request.Header.Get("X-Request-Id"))
			s.serverError(response, challengeErr)
			return
		}
		// Keep a uniform accepted response for unknown or ineligible addresses.
		s.logger.Info("ZITADEL email OTP was not issued", "status", apiError.StatusCode, "request_id", request.Header.Get("X-Request-Id"))
	}
	if err := s.transactions.putAttempt(request.Context(), input.TransactionID, attempt); err != nil {
		if challenge.SessionID != "" {
			_ = s.zitadel.DeleteSession(request.Context(), challenge.SessionID, challenge.SessionToken)
		}
		s.serverError(response, err)
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]any{"status": "code_sent", "resendAfter": 60})
}

func (s *Service) VerifyEmailCode(response http.ResponseWriter, request *http.Request) {
	if !s.validOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	var input struct {
		TransactionID string `json:"transactionId"`
		Code          string `json:"code"`
		CSRFToken     string `json:"csrfToken"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	input.Code = strings.TrimSpace(input.Code)
	csrfCookie, err := request.Cookie(csrfCookieName)
	if err != nil || input.CSRFToken == "" || !constantEqual(csrfCookie.Value, input.CSRFToken) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_csrf"})
		return
	}
	if input.TransactionID == "" || len(input.TransactionID) > 128 || input.Code == "" || len(input.Code) > 32 {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_code"})
		return
	}
	attempt, err := s.transactions.getAttempt(request.Context(), input.TransactionID)
	if err != nil || !attempt.OTPChallengeRequested {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "expired_login"})
		return
	}
	if !constantEqual(attempt.CSRFToken, input.CSRFToken) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_csrf"})
		return
	}
	allowed, err := s.transactions.allowAttempt(
		request.Context(),
		"email-code-verify|"+clientIdentity(request)+"|"+attempt.Email,
	)
	if err != nil {
		s.serverError(response, err)
		return
	}
	if !allowed {
		writeJSON(response, http.StatusTooManyRequests, map[string]string{"error": "try_again_later"})
		return
	}
	if attempt.OTPSessionID == "" {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "invalid_code"})
		return
	}

	upstreamSession, err := s.zitadel.VerifyEmailOTP(request.Context(), attempt.OTPSessionID, input.Code)
	if err != nil {
		var apiError *zitadel.APIError
		if errors.As(err, &apiError) && apiError.StatusCode >= 400 && apiError.StatusCode < 500 {
			writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "invalid_code"})
			return
		}
		s.logger.Warn("verify ZITADEL email OTP failed", "error", err, "request_id", request.Header.Get("X-Request-Id"))
		s.serverError(response, err)
		return
	}
	if err := s.transactions.deleteAttempt(request.Context(), input.TransactionID); err != nil {
		_ = s.zitadel.DeleteSession(request.Context(), upstreamSession.ID, upstreamSession.Token)
		s.serverError(response, err)
		return
	}

	if err := s.createEmailSession(request.Context(), response, attempt, upstreamSession); err != nil {
		s.serverError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"redirect": attempt.ReturnTo})
}

func (s *Service) EmailCodeCallback(response http.ResponseWriter, request *http.Request) {
	transactionID := strings.TrimSpace(request.URL.Query().Get("transaction_id"))
	code := strings.TrimSpace(request.URL.Query().Get("code"))
	if transactionID == "" || len(transactionID) > 128 || code == "" || len(code) > 32 {
		s.redirectEmailCodeResult(response, request, "invalid")
		return
	}
	attempt, err := s.transactions.getAttempt(request.Context(), transactionID)
	if err != nil || !attempt.OTPChallengeRequested || attempt.OTPSessionID == "" {
		s.redirectEmailCodeResult(response, request, "expired")
		return
	}
	csrfCookie, err := request.Cookie(csrfCookieName)
	if err != nil || !constantEqual(csrfCookie.Value, attempt.CSRFToken) {
		s.redirectEmailCodeResult(response, request, "browser")
		return
	}
	allowed, err := s.transactions.allowAttempt(
		request.Context(),
		"email-code-link|"+clientIdentity(request)+"|"+attempt.Email,
	)
	if err != nil {
		s.logger.Warn("rate limit email OTP callback", "error", err)
		s.redirectEmailCodeResult(response, request, "error")
		return
	}
	if !allowed {
		s.redirectEmailCodeResult(response, request, "rate_limited")
		return
	}

	upstreamSession, err := s.zitadel.VerifyEmailOTP(request.Context(), attempt.OTPSessionID, code)
	if err != nil {
		var apiError *zitadel.APIError
		if !errors.As(err, &apiError) || apiError.StatusCode < 400 || apiError.StatusCode >= 500 {
			s.logger.Warn("verify ZITADEL email OTP callback failed", "error", err, "request_id", request.Header.Get("X-Request-Id"))
			s.redirectEmailCodeResult(response, request, "error")
			return
		}
		s.redirectEmailCodeResult(response, request, "invalid")
		return
	}
	if err := s.transactions.deleteAttempt(request.Context(), transactionID); err != nil {
		_ = s.zitadel.DeleteSession(request.Context(), upstreamSession.ID, upstreamSession.Token)
		s.redirectEmailCodeResult(response, request, "error")
		return
	}
	if err := s.createEmailSession(request.Context(), response, attempt, upstreamSession); err != nil {
		s.logger.Warn("create platform session from email OTP callback", "error", err)
		s.redirectEmailCodeResult(response, request, "error")
		return
	}
	http.Redirect(response, request, attempt.ReturnTo, http.StatusSeeOther)
}

func (s *Service) createEmailSession(
	ctx context.Context,
	response http.ResponseWriter,
	attempt loginAttempt,
	upstreamSession zitadel.Session,
) error {
	profile, profileErr := s.zitadel.GetUserByID(ctx, upstreamSession.Subject)
	if profileErr != nil {
		s.logger.Warn("load ZITADEL profile after email OTP authentication", "error", profileErr)
	}
	now := time.Now().UTC()
	sessionID, err := randomValue(32)
	if err != nil {
		_ = s.zitadel.DeleteSession(ctx, upstreamSession.ID, upstreamSession.Token)
		return err
	}
	value := session.Session{
		AssertionSessionID:    sessionID,
		Subject:               upstreamSession.Subject,
		Entitlements:          append([]string(nil), s.cfg.DefaultEntitlements...),
		PlatformRoles:         s.platformRoles(ctx, upstreamSession.Subject),
		AuthenticationTime:    now,
		AuthenticationMethods: []string{"otp"},
		Email:                 firstNonEmpty(profile.Email, attempt.Email),
		DisplayName:           firstNonEmpty(profile.DisplayName, upstreamSession.DisplayName, upstreamSession.LoginName),
		PreferredUsername:     firstNonEmpty(profile.LoginName, upstreamSession.LoginName),
		UpstreamSessionID:     upstreamSession.ID,
		UpstreamSessionToken:  upstreamSession.Token,
		CreatedAt:             now,
		LastSeenAt:            now,
	}
	if value.Subject == "" {
		_ = s.zitadel.DeleteSession(ctx, upstreamSession.ID, upstreamSession.Token)
		return errors.New("ZITADEL session does not include a user subject")
	}
	if err := s.sessions.Put(ctx, sessionID, value); err != nil {
		_ = s.zitadel.DeleteSession(ctx, upstreamSession.ID, upstreamSession.Token)
		return err
	}
	clearCSRFCookie(response)
	s.setSessionCookie(response, sessionID, int(s.cfg.AbsoluteTTL.Seconds()))
	return nil
}

func (s *Service) redirectEmailCodeResult(response http.ResponseWriter, request *http.Request, status string) {
	target := strings.TrimRight(s.cfg.PublicOrigin, "/") + "/login?mode=email&email_status=" + url.QueryEscape(status)
	http.Redirect(response, request, target, http.StatusSeeOther)
}

func (s *Service) Callback(response http.ResponseWriter, request *http.Request) {
	state := request.URL.Query().Get("state")
	tx, err := s.transactions.getTransaction(request.Context(), state)
	if err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_callback"})
		return
	}
	_ = s.transactions.deleteTransaction(request.Context(), state)
	if tx.Federated {
		s.federatedCallback(response, request, tx)
		return
	}
	if oidcError := request.URL.Query().Get("error"); oidcError != "" {
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	code := request.URL.Query().Get("code")
	if code == "" {
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	oauthConfig, verifier, oidcHTTP, err := s.oidcConfiguration(request.Context())
	if err != nil {
		s.logger.Error("configure OIDC callback", "error", err)
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	ctx := oidc.ClientContext(request.Context(), oidcHTTP)
	token, err := oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(tx.PKCEVerifier))
	if err != nil {
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	var claims identityClaims
	if err := idToken.Claims(&claims); err != nil {
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	if !constantEqual(claims.Nonce, tx.Nonce) || claims.Subject == "" {
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	now := time.Now().UTC()
	authenticationTime := now
	if claims.AuthTime > 0 {
		authenticationTime = time.Unix(claims.AuthTime, 0).UTC()
	}
	sessionID, err := randomValue(32)
	if err != nil {
		s.logger.Error("create federated session", "error", err)
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	// The business context always starts personal: the ZITADEL resident
	// organization of the account is identity plumbing, not a tenant.
	value := session.Session{
		AssertionSessionID:    sessionID,
		Subject:               claims.Subject,
		Entitlements:          append([]string(nil), s.cfg.DefaultEntitlements...),
		PlatformRoles:         s.platformRoles(request.Context(), claims.Subject),
		AuthenticationTime:    authenticationTime,
		AuthenticationMethods: []string{"federated"},
		Email:                 claims.Email,
		DisplayName:           firstNonEmpty(claims.Name, claims.PreferredUsername),
		PreferredUsername:     claims.PreferredUsername,
		CreatedAt:             now,
		LastSeenAt:            now,
	}
	if err := s.sessions.Put(request.Context(), sessionID, value); err != nil {
		s.logger.Error("store federated session", "error", err)
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	s.setSessionCookie(response, sessionID, int(s.cfg.AbsoluteTTL.Seconds()))
	s.redirectOIDCResult(response, request, tx.ReturnTo, "success")
}

func (s *Service) federatedCallback(response http.ResponseWriter, request *http.Request, tx transaction) {
	query := request.URL.Query()
	s.logger.Info("federated callback received", "provider", tx.Provider, "has_error", query.Get("error") != "")
	if query.Get("error") != "" {
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	intentID, intentToken := identityProviderIntentCredentials(query)
	if intentID == "" || intentToken == "" {
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	info, err := s.zitadel.RetrieveIdentityProviderIntent(request.Context(), intentID, intentToken)
	if err != nil || info.IDPID != s.cfg.OIDCProviderIDs[tx.Provider] || info.UserID == "" {
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	if info.LinkedUserID != "" {
		if err := s.createFederatedSession(request.Context(), response, info.LinkedUserID, info); err != nil {
			s.logger.Error("create federated session", "error", err)
			s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
			return
		}
		s.redirectOIDCResult(response, request, tx.ReturnTo, "success")
		return
	}
	registrationID, err := randomValue(32)
	if err != nil {
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	csrf, err := randomValue(32)
	if err != nil {
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	pending := federatedRegistration{
		TransactionID:    registrationID,
		CSRFToken:        csrf,
		Provider:         tx.Provider,
		IDPID:            info.IDPID,
		ExternalUserID:   info.UserID,
		ExternalUserName: firstNonEmpty(info.UserName, info.UserID),
		SuggestedEmail:   info.Email,
		SuggestedName:    info.DisplayName,
		ReturnTo:         tx.ReturnTo,
		CreatedAt:        time.Now().UTC(),
	}
	if err := s.transactions.putFederatedRegistration(request.Context(), pending); err != nil {
		s.logger.Error("store federated registration", "error", err)
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	location := "/register?" + url.Values{
		"mode":           {"federated"},
		"transaction_id": {registrationID},
		"return_to":      {tx.ReturnTo},
	}.Encode()
	http.Redirect(response, request, location, http.StatusFound)
}

func (s *Service) createFederatedSession(
	ctx context.Context,
	response http.ResponseWriter,
	subject string,
	info zitadel.IDPInformation,
) error {
	if subject == "" {
		return errors.New("federated identity does not include a user subject")
	}
	if info.Email == "" || info.DisplayName == "" || info.UserName == "" {
		if profile, err := s.zitadel.GetUserByID(ctx, subject); err == nil {
			info.Email = firstNonEmpty(info.Email, profile.Email)
			info.DisplayName = firstNonEmpty(info.DisplayName, profile.DisplayName)
			info.UserName = firstNonEmpty(info.UserName, profile.LoginName)
		} else {
			s.logger.Warn("load ZITADEL profile after federated authentication", "error", err)
		}
	}
	now := time.Now().UTC()
	sessionID, err := randomValue(32)
	if err != nil {
		return err
	}
	value := session.Session{
		AssertionSessionID:    sessionID,
		Subject:               subject,
		Entitlements:          append([]string(nil), s.cfg.DefaultEntitlements...),
		PlatformRoles:         s.platformRoles(ctx, subject),
		AuthenticationTime:    now,
		AuthenticationMethods: []string{"federated"},
		Email:                 info.Email,
		DisplayName:           firstNonEmpty(info.DisplayName, info.UserName),
		PreferredUsername:     info.UserName,
		CreatedAt:             now,
		LastSeenAt:            now,
	}
	if err := s.sessions.Put(ctx, sessionID, value); err != nil {
		return err
	}
	s.setSessionCookie(response, sessionID, int(s.cfg.AbsoluteTTL.Seconds()))
	return nil
}

// StartIDPLink begins a server-bound account linking transaction. The current
// session subject is never taken from a browser-controlled query parameter.
func (s *Service) StartIDPLink(response http.ResponseWriter, request *http.Request) {
	value, _, err := s.currentSession(request)
	if err != nil || value.Subject == "" {
		http.Redirect(response, request, strings.TrimRight(s.cfg.PublicOrigin, "/")+"/login", http.StatusFound)
		return
	}
	provider := strings.ToLower(strings.TrimSpace(request.URL.Query().Get("provider")))
	providerID, ok := s.cfg.OIDCProviderIDs[provider]
	if !ok {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "unsupported_provider"})
		return
	}
	state, err := randomValue(32)
	if err != nil {
		s.serverError(response, err)
		return
	}
	returnTo := s.safeReturnTo(request.URL.Query().Get("return_to"))
	if !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") {
		returnTo = "/account"
	}
	if err := s.transactions.putLinkTransaction(request.Context(), linkTransaction{
		State: state, Subject: value.Subject, Provider: provider, ReturnTo: returnTo, CreatedAt: time.Now().UTC(),
	}); err != nil {
		s.serverError(response, err)
		return
	}
	callback := strings.TrimRight(s.cfg.PublicOrigin, "/") + "/api/auth/idp-links/callback?state=" + url.QueryEscape(state)
	failure := strings.TrimRight(s.cfg.PublicOrigin, "/") + "/account?link_status=error&provider=" + url.QueryEscape(provider)
	authURL, err := s.zitadel.StartIdentityProviderIntent(request.Context(), providerID, callback, failure)
	if err != nil {
		_ = s.transactions.deleteLinkTransaction(request.Context(), state)
		s.serverError(response, err)
		return
	}
	http.Redirect(response, request, authURL, http.StatusFound)
}

func (s *Service) IDPLinkCallback(response http.ResponseWriter, request *http.Request) {
	requestID := request.Header.Get("X-Request-Id")
	query := request.URL.Query()
	s.logger.Info("IDP link callback received", "request_id", requestID, "has_error", query.Get("error") != "")
	state := query.Get("state")
	tx, err := s.transactions.getLinkTransaction(request.Context(), state)
	if err != nil {
		s.logger.Warn("IDP link transaction not found", "request_id", requestID, "error", err)
		http.Redirect(response, request, strings.TrimRight(s.cfg.PublicOrigin, "/")+"/account?link_status=error", http.StatusFound)
		return
	}
	_ = s.transactions.deleteLinkTransaction(request.Context(), state)
	if query.Get("error") != "" {
		s.logger.Info("IDP provider returned error", "request_id", requestID, "provider", tx.Provider, "idp_error", query.Get("error"))
		http.Redirect(response, request, s.linkResultURL(tx.ReturnTo, tx.Provider, "error"), http.StatusFound)
		return
	}
	intentID, intentToken := identityProviderIntentCredentials(query)
	if intentID == "" || intentToken == "" {
		s.logger.Warn("IDP link callback missing intent credentials", "request_id", requestID, "provider", tx.Provider, "has_intent_id", intentID != "", "has_intent_token", intentToken != "")
		http.Redirect(response, request, s.linkResultURL(tx.ReturnTo, tx.Provider, "error"), http.StatusFound)
		return
	}
	info, err := s.zitadel.RetrieveIdentityProviderIntent(request.Context(), intentID, intentToken)
	expectedID := s.cfg.OIDCProviderIDs[tx.Provider]
	if err != nil {
		s.logger.Error("IDP retrieve identity provider intent failed", "request_id", requestID, "provider", tx.Provider, "intentID", intentID, "error", err)
		http.Redirect(response, request, s.linkResultURL(tx.ReturnTo, tx.Provider, "error"), http.StatusFound)
		return
	}
	if info.IDPID != expectedID {
		s.logger.Error("IDP provider ID mismatch", "request_id", requestID, "provider", tx.Provider, "expected", expectedID, "got", info.IDPID)
		http.Redirect(response, request, s.linkResultURL(tx.ReturnTo, tx.Provider, "error"), http.StatusFound)
		return
	}
	if info.UserID == "" {
		s.logger.Error("IDP intent returned empty user ID", "request_id", requestID, "provider", tx.Provider, "idpId", info.IDPID)
		http.Redirect(response, request, s.linkResultURL(tx.ReturnTo, tx.Provider, "error"), http.StatusFound)
		return
	}
	if err := s.zitadel.AddIDPLink(request.Context(), tx.Subject, zitadel.IDPLink{
		IDPID: info.IDPID, UserID: info.UserID, UserName: firstNonEmpty(info.UserName, info.UserID),
	}); err != nil {
		if apiErr, ok := err.(*zitadel.APIError); ok && apiErr.StatusCode == http.StatusConflict {
			s.logger.Info("IDP link already exists on another account", "request_id", requestID, "provider", tx.Provider, "subject", tx.Subject, "externalUserID", info.UserID)
			http.Redirect(response, request, s.linkResultURL(tx.ReturnTo, tx.Provider, "conflict"), http.StatusFound)
			return
		}
		s.logger.Error("IDP add link failed", "request_id", requestID, "provider", tx.Provider, "subject", tx.Subject, "externalUserID", info.UserID, "error", err)
		http.Redirect(response, request, s.linkResultURL(tx.ReturnTo, tx.Provider, "error"), http.StatusFound)
		return
	}
	s.logger.Info("IDP link added successfully", "request_id", requestID, "provider", tx.Provider, "subject", tx.Subject, "externalUserID", info.UserID)
	http.Redirect(response, request, s.linkResultURL(tx.ReturnTo, tx.Provider, "success"), http.StatusFound)
}

func (s *Service) ListIDPLinks(response http.ResponseWriter, request *http.Request) {
	value, _, err := s.currentSession(request)
	if err != nil || value.Subject == "" {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	links, err := s.zitadel.ListIDPLinks(request.Context(), value.Subject)
	if err != nil {
		s.serverError(response, err)
		return
	}
	result := make([]map[string]string, 0, len(links))
	for _, link := range links {
		provider := ""
		for name, id := range s.cfg.OIDCProviderIDs {
			if id == link.IDPID {
				provider = name
				break
			}
		}
		if provider == "" {
			continue
		}
		result = append(result, map[string]string{"provider": provider, "userId": link.UserID, "userName": link.UserName})
	}
	writeJSON(response, http.StatusOK, map[string]any{"links": result})
}

func (s *Service) linkResultURL(returnTo, provider, status string) string {
	if !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") {
		return strings.TrimRight(s.cfg.PublicOrigin, "/") + "/account?link_status=" + url.QueryEscape(status) + "&provider=" + url.QueryEscape(provider)
	}
	separator := "?"
	if strings.Contains(returnTo, "?") {
		separator = "&"
	}
	return returnTo + separator + "link_status=" + url.QueryEscape(status) + "&provider=" + url.QueryEscape(provider)
}

func (s *Service) redirectOIDCResult(response http.ResponseWriter, request *http.Request, returnTo, status string) {
	if strings.HasPrefix(returnTo, "/") && !strings.HasPrefix(returnTo, "//") {
		location := "/auth/callback?status=" + url.QueryEscape(status) + "&return_to=" + url.QueryEscape(returnTo)
		http.Redirect(response, request, location, http.StatusFound)
		return
	}
	if status == "success" {
		http.Redirect(response, request, returnTo, http.StatusFound)
		return
	}
	writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "oidc_failed"})
}

func (s *Service) Session(response http.ResponseWriter, request *http.Request) {
	value, _, err := s.currentSession(request)
	if err != nil {
		writeJSON(response, http.StatusUnauthorized, map[string]any{"authenticated": false})
		return
	}
	var organization any
	if value.OrganizationID != "" {
		organization = map[string]string{
			"id":   value.OrganizationID,
			"name": value.OrganizationName,
		}
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"authenticated":     true,
		"subject":           value.Subject,
		"displayName":       value.DisplayName,
		"email":             value.Email,
		"preferredUsername": value.PreferredUsername,
		"entitlements":      value.Entitlements,
		"organization":      organization,
		"roles":             value.Roles,
		"platformRoles":     value.PlatformRoles,
	})
}

// Profile returns the canonical current-user profile from ZITADEL. Session
// data remains a small authentication summary and is not the profile source.
func (s *Service) Profile(response http.ResponseWriter, request *http.Request) {
	value, sessionID, err := s.currentSession(request)
	if err != nil {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	profile, err := s.zitadel.GetUserByID(request.Context(), value.Subject)
	if err != nil {
		var apiError *zitadel.APIError
		if errors.As(err, &apiError) && apiError.StatusCode == http.StatusNotFound {
			writeJSON(response, http.StatusNotFound, map[string]string{"error": "profile_not_found"})
			return
		}
		s.serverError(response, err)
		return
	}
	if value.Email != profile.Email || value.DisplayName != profile.DisplayName || value.PreferredUsername != profile.LoginName {
		value.Email = profile.Email
		value.DisplayName = profile.DisplayName
		value.PreferredUsername = profile.LoginName
		if err := s.sessions.Put(request.Context(), sessionID, value); err != nil {
			s.logger.Warn("refresh session profile summary", "error", err)
		}
	}
	avatarURL, _ := s.zitadel.GetUserMetadata(request.Context(), value.Subject, "avatar_url")
	writeJSON(response, http.StatusOK, map[string]any{
		"id":                profile.ID,
		"loginName":         profile.LoginName,
		"displayName":       profile.DisplayName,
		"givenName":         profile.GivenName,
		"familyName":        profile.FamilyName,
		"nickName":          profile.NickName,
		"preferredLanguage": profile.PreferredLanguage,
		"gender":            profile.Gender,
		"email":             profile.Email,
		"emailVerified":     profile.EmailVerified,
		"phone":             profile.Phone,
		"phoneVerified":     profile.PhoneVerified,
		"state":             profile.State,
		"avatarURL":         avatarURL,
	})
}

// s3Put uploads content to the configured S3-compatible bucket using AWS
// Signature V4. The object key includes an "avatars/" prefix for namespacing.
func (s *Service) s3Put(ctx context.Context, key, contentType string, body io.Reader) error {
	endpoint := s.cfg.S3Endpoint
	bucket := s.cfg.S3Bucket
	accessKey := s.cfg.S3AccessKey
	secretKey := s.cfg.S3SecretKey
	scheme := "http"
	if s.cfg.S3UseSSL {
		scheme = "https"
	}
	putURL := fmt.Sprintf("%s://%s/%s/%s", scheme, endpoint, bucket, key)

	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("read body for S3 upload: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPut, putURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("create S3 request: %w", err)
	}
	request.Header.Set("Content-Type", contentType)
	request.Host = endpoint
	request.Header.Set("Host", endpoint)

	// AWS Signature V4
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	region := "us-east-1"
	service_name := "s3"

	bodyHash := sha256HexContentBytes(bodyBytes)
	request.Header.Set("x-amz-content-sha256", bodyHash)
	request.Header.Set("x-amz-date", amzDate)

	canonicalHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonicalRequest := request.Method + "\n" +
		request.URL.Path + "\n" +
		"\n" +
		"host:" + request.Host + "\n" +
		"x-amz-content-sha256:" + bodyHash + "\n" +
		"x-amz-date:" + amzDate + "\n" +
		"\n" +
		strings.Join(canonicalHeaders, ";") + "\n" +
		bodyHash

	algorithm := "AWS4-HMAC-SHA256"
	credentialScope := dateStamp + "/" + region + "/" + service_name + "/aws4_request"
	stringToSign := algorithm + "\n" + amzDate + "\n" + credentialScope + "\n" +
		sha256HexContentBytes([]byte(canonicalRequest))

	mac := func(key, data []byte) []byte {
		m := hmac.New(sha256.New, key)
		m.Write(data)
		return m.Sum(nil)
	}
	signingKey := mac([]byte("AWS4"+secretKey), []byte(dateStamp))
	signingKey = mac(signingKey, []byte(region))
	signingKey = mac(signingKey, []byte(service_name))
	signingKey = mac(signingKey, []byte("aws4_request"))
	signature := hex.EncodeToString(mac(signingKey, []byte(stringToSign)))

	authHeader := algorithm + " Credential=" + accessKey + "/" + credentialScope +
		", SignedHeaders=" + strings.Join(canonicalHeaders, ";") +
		", Signature=" + signature
	request.Header.Set("Authorization", authHeader)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("S3 PUT request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return fmt.Errorf("S3 PUT failed with status %d: %s", response.StatusCode, string(respBody))
	}
	return nil
}

func sha256HexContentBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// UploadAvatar accepts a multipart file upload, stores the file in the
// configured S3-compatible bucket, updates the user profile with the avatar
// URL, and returns the updated profile.
func (s *Service) UploadAvatar(response http.ResponseWriter, request *http.Request) {
	value, sessionID, err := s.currentSession(request)
	if err != nil {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	// Limit upload size to 5MB.
	request.Body = http.MaxBytesReader(nil, request.Body, 5<<20)

	if err := request.ParseMultipartForm(5 << 20); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "file_too_large_or_invalid"})
		return
	}
	file, header, err := request.FormFile("file")
	if err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "missing_file"})
		return
	}
	defer file.Close()

	// Validate file type by extension / content type.
	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	allowedTypes := map[string]bool{
		"image/jpeg": true, "image/png": true, "image/gif": true, "image/webp": true,
	}
	if !allowedTypes[contentType] {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "unsupported_file_type"})
		return
	}

	// Read file content for hash.
	content, err := io.ReadAll(file)
	if err != nil {
		s.serverError(response, err)
		return
	}

	// Compute SHA256 hash for content-addressed storage.
	hasher := sha256.New()
	hasher.Write(content)
	hash := hex.EncodeToString(hasher.Sum(nil))

	// S3 key: avatars/{hash}{ext}
	ext := path.Ext(header.Filename)
	key := "avatars/" + hash + ext

	// Upload to S3.
	if err := s.s3Put(request.Context(), key, contentType, bytes.NewReader(content)); err != nil {
		s.logger.Error("S3 avatar upload", "error", err)
		writeJSON(response, http.StatusInternalServerError, map[string]string{"error": "upload_failed"})
		return
	}

	avatarURL := fmt.Sprintf("%s/%s/%s", s.cfg.StaticBaseURL, s.cfg.S3Bucket, key)

	// Persist avatar URL as ZITADEL user metadata.
	if err := s.zitadel.SetUserMetadata(request.Context(), value.Subject, "avatar_url", avatarURL); err != nil {
		s.logger.Warn("set avatar metadata in ZITADEL", "error", err)
	}

	// Reload updated profile and refresh session.
	updated, err := s.zitadel.GetUserByID(request.Context(), value.Subject)
	if err != nil {
		s.serverError(response, err)
		return
	}
	if value.Email != updated.Email || value.DisplayName != updated.DisplayName || value.PreferredUsername != updated.LoginName {
		value.Email = updated.Email
		value.DisplayName = updated.DisplayName
		value.PreferredUsername = updated.LoginName
		if err := s.sessions.Put(request.Context(), sessionID, value); err != nil {
			s.logger.Warn("refresh session after avatar upload", "error", err)
		}
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"avatarURL":   avatarURL,
		"hash":        hash,
		"id":          updated.ID,
		"loginName":   updated.LoginName,
		"displayName": updated.DisplayName,
		"email":       updated.Email,
	})
}

// UpdateProfile accepts a PATCH body with profile fields to update on the
// authenticated user's ZITADEL human profile.
func (s *Service) UpdateProfile(response http.ResponseWriter, request *http.Request) {
	value, sessionID, err := s.currentSession(request)
	if err != nil {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var input struct {
		DisplayName       string `json:"displayName"`
		GivenName         string `json:"givenName"`
		FamilyName        string `json:"familyName"`
		NickName          string `json:"nickName"`
		PreferredLanguage string `json:"preferredLanguage"`
		Gender            string `json:"gender"`
		Email             string `json:"email"`
		Phone             string `json:"phone"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	profile := map[string]any{}
	profilePayload := map[string]any{}
	if input.DisplayName != "" {
		profilePayload["displayName"] = input.DisplayName
	}
	if input.GivenName != "" {
		profilePayload["givenName"] = input.GivenName
	}
	if input.FamilyName != "" {
		profilePayload["familyName"] = input.FamilyName
	}
	if input.NickName != "" {
		profilePayload["nickName"] = input.NickName
	}
	if input.PreferredLanguage != "" {
		profilePayload["preferredLanguage"] = input.PreferredLanguage
	}
	if input.Gender != "" {
		profilePayload["gender"] = input.Gender
	}
	if len(profilePayload) > 0 {
		profile["profile"] = profilePayload
	}
	if input.Email != "" {
		profile["email"] = input.Email
	}
	if input.Phone != "" {
		profile["phone"] = input.Phone
	}

	if len(profile) == 0 {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "no_fields_to_update"})
		return
	}

	if err := s.zitadel.UpdateHumanUser(request.Context(), value.Subject, profile); err != nil {
		var apiError *zitadel.APIError
		if errors.As(err, &apiError) && apiError.StatusCode == http.StatusNotFound {
			writeJSON(response, http.StatusNotFound, map[string]string{"error": "profile_not_found"})
			return
		}
		s.serverError(response, err)
		return
	}

	updated, err := s.zitadel.GetUserByID(request.Context(), value.Subject)
	if err != nil {
		s.serverError(response, err)
		return
	}
	if value.Email != updated.Email || value.DisplayName != updated.DisplayName || value.PreferredUsername != updated.LoginName {
		value.Email = updated.Email
		value.DisplayName = updated.DisplayName
		value.PreferredUsername = updated.LoginName
		if err := s.sessions.Put(request.Context(), sessionID, value); err != nil {
			s.logger.Warn("refresh session after profile update", "error", err)
		}
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"id":                updated.ID,
		"loginName":         updated.LoginName,
		"displayName":       updated.DisplayName,
		"givenName":         updated.GivenName,
		"familyName":        updated.FamilyName,
		"nickName":          updated.NickName,
		"preferredLanguage": updated.PreferredLanguage,
		"gender":            updated.Gender,
		"email":             updated.Email,
		"emailVerified":     updated.EmailVerified,
		"phone":             updated.Phone,
		"phoneVerified":     updated.PhoneVerified,
		"state":             updated.State,
	})
}

// ResolveSession exposes cookie session resolution to sibling services that
// operate on the authenticated session, such as the organization API.
func (s *Service) ResolveSession(request *http.Request) (session.Session, string, error) {
	return s.currentSession(request)
}

func (s *Service) Logout(response http.ResponseWriter, request *http.Request) {
	if !s.validOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	value, sessionID, err := s.currentSession(request)
	if err == nil {
		_ = s.sessions.Revoke(request.Context(), sessionID, time.Now().UTC())
		if err := s.zitadel.DeleteSession(request.Context(), value.UpstreamSessionID, value.UpstreamSessionToken); err != nil {
			s.logger.Warn("delete upstream session", "error", err)
		}
	}
	s.setSessionCookie(response, "", -1)
	writeJSON(response, http.StatusOK, map[string]string{"redirect": "/"})
}

func (s *Service) currentSession(request *http.Request) (session.Session, string, error) {
	cookie, err := request.Cookie(s.cfg.SessionCookieName)
	if err != nil || cookie.Value == "" {
		return session.Session{}, "", session.ErrNotFound
	}
	value, err := s.sessions.Get(request.Context(), cookie.Value)
	if err != nil {
		return session.Session{}, "", err
	}
	now := time.Now().UTC()
	if !value.RevokedAt.IsZero() || now.Sub(value.LastSeenAt) > s.cfg.IdleTTL || now.Sub(value.CreatedAt) > s.cfg.AbsoluteTTL {
		return session.Session{}, "", session.ErrNotFound
	}
	if now.Sub(value.LastSeenAt) > 5*time.Minute {
		value.LastSeenAt = now
		_ = s.sessions.Put(request.Context(), cookie.Value, value)
	}
	return value, cookie.Value, nil
}

func (s *Service) setSessionCookie(response http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(response, &http.Cookie{
		Name:     s.cfg.SessionCookieName,
		Value:    value,
		Path:     "/",
		Domain:   s.cfg.SessionCookieDomain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) validOrigin(request *http.Request) bool {
	origin := request.Header.Get("Origin")
	if origin == s.cfg.PublicOrigin {
		return true
	}
	// First-party product origins (for example opc.shiguanglab.com) may call
	// logout and context endpoints directly; they share the session cookie.
	for _, allowed := range s.cfg.AllowedReturnOrigins {
		if origin == strings.TrimRight(allowed, "/") {
			return true
		}
	}
	return false
}

func (s *Service) LoginLocation(scheme, host, path string) string {
	if scheme == "" {
		scheme = "https"
	}
	target := path
	publicOrigin, err := url.Parse(s.cfg.PublicOrigin)
	if err == nil && !strings.EqualFold(host, publicOrigin.Host) {
		target = scheme + "://" + host + path
	}
	return strings.TrimRight(s.cfg.PublicOrigin, "/") + "/login?return_to=" +
		url.QueryEscape(s.safeReturnTo(target))
}

func (s *Service) oidcConfiguration(ctx context.Context) (oauth2.Config, *oidc.IDTokenVerifier, *http.Client, error) {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	if s.verifier != nil && s.oidcHTTP != nil {
		return s.oauth, s.verifier, s.oidcHTTP, nil
	}
	if s.cfg.OIDCClientID == "" || s.cfg.OIDCClientSecret == "" || s.cfg.OIDCRedirectURL == "" {
		return oauth2.Config{}, nil, nil, errors.New("OIDC federation is not configured")
	}
	oidcHTTP, err := zitadel.NewRewriteHTTPClient(s.cfg.ZitadelIssuer, s.cfg.ZitadelInternalURL)
	if err != nil {
		return oauth2.Config{}, nil, nil, err
	}
	discoveryContext := oidc.ClientContext(ctx, oidcHTTP)
	provider, err := oidc.NewProvider(discoveryContext, s.cfg.ZitadelIssuer)
	if err != nil {
		return oauth2.Config{}, nil, nil, fmt.Errorf("discover ZITADEL OIDC provider: %w", err)
	}
	s.oidcHTTP = oidcHTTP
	s.oauth = oauth2.Config{
		ClientID:     s.cfg.OIDCClientID,
		ClientSecret: s.cfg.OIDCClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  s.cfg.OIDCRedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	s.verifier = provider.Verifier(&oidc.Config{ClientID: s.cfg.OIDCClientID})
	return s.oauth, s.verifier, s.oidcHTTP, nil
}

// platformRoles resolves context-independent roles granted on the platform
// project's own organization. Failures degrade to no extra roles: a directory
// hiccup must never block login, only reduce privileges.
func (s *Service) platformRoles(ctx context.Context, userID string) []string {
	if s.cfg.ZitadelProjectID == "" || s.cfg.ZitadelOrganizationID == "" {
		return nil
	}
	authorizations, err := s.zitadel.ListAuthorizations(ctx, zitadel.AuthorizationFilter{
		UserID:         userID,
		OrganizationID: s.cfg.ZitadelOrganizationID,
		ProjectID:      s.cfg.ZitadelProjectID,
		ActiveOnly:     true,
	})
	if err != nil {
		s.logger.Warn("resolve platform roles", "error", err)
		return nil
	}
	roles := make([]string, 0, 4)
	for _, authorization := range authorizations {
		roles = append(roles, authorization.Roles...)
	}
	return roles
}

func (s *Service) serverError(response http.ResponseWriter, err error) {
	s.logger.Error("login request failed", "error", err)
	writeJSON(response, http.StatusInternalServerError, map[string]string{"error": "temporarily_unavailable"})
}

func (s *Service) safeReturnTo(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/"
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil {
		return "/"
	}
	if !parsed.IsAbs() {
		if strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") && parsed.Host == "" {
			return value
		}
		return "/"
	}
	origin := strings.ToLower(parsed.Scheme + "://" + parsed.Host)
	for _, allowed := range append([]string{s.cfg.PublicOrigin}, s.cfg.AllowedReturnOrigins...) {
		allowedURL, err := url.Parse(strings.TrimRight(allowed, "/"))
		if err == nil && origin == strings.ToLower(allowedURL.Scheme+"://"+allowedURL.Host) {
			return value
		}
	}
	return "/"
}

func randomValue(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func constantEqual(left, right string) bool {
	leftSum := sha256.Sum256([]byte(left))
	rightSum := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftSum[:], rightSum[:]) == 1
}

func clientIdentity(request *http.Request) string {
	value := strings.TrimSpace(strings.Split(request.Header.Get("X-Forwarded-For"), ",")[0])
	if value != "" {
		return value
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil {
		return host
	}
	return request.RemoteAddr
}

func clearCSRFCookie(response http.ResponseWriter) {
	http.SetCookie(response, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func decodeJSON(request *http.Request, value any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(nil, request.Body, 16<<10))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func identityProviderIntentCredentials(query url.Values) (string, string) {
	return firstNonEmpty(query.Get("id"), query.Get("idp_intent_id"), query.Get("idpIntentId")),
		firstNonEmpty(query.Get("token"), query.Get("idp_intent_token"), query.Get("idpIntentToken"))
}

func containsLetter(value string) bool {
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' {
			return true
		}
	}
	return false
}

func containsDigit(value string) bool {
	for _, character := range value {
		if character >= '0' && character <= '9' {
			return true
		}
	}
	return false
}
