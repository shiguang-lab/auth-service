package login

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
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

var (
	usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)
	emailPattern    = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
)

type Service struct {
	cfg           config.Config
	sessions      session.Store
	transactions  transactionRepository
	zitadel       zitadelSessionClient
	oidcMu        sync.Mutex
	oidcHTTP      *http.Client
	oauth         oauth2.Config
	verifier      *oidc.IDTokenVerifier
	logger        *slog.Logger
	roleRefresher platformRoleRefresher
}

type platformRoleRefresher interface {
	Refresh(context.Context, string, session.Session) (session.Session, error)
}

type transactionRepository interface {
	putTransaction(context.Context, transaction) error
	getTransaction(context.Context, string) (transaction, error)
	deleteTransaction(context.Context, string) error
	putLinkTransaction(context.Context, linkTransaction) error
	getLinkTransaction(context.Context, string) (linkTransaction, error)
	deleteLinkTransaction(context.Context, string) error
	putAttempt(context.Context, string, loginAttempt) error
	takeAttempt(context.Context, string) (loginAttempt, error)
	putFederatedRegistration(context.Context, federatedRegistration) error
	getFederatedRegistration(context.Context, string) (federatedRegistration, error)
	takeFederatedRegistration(context.Context, string) (federatedRegistration, error)
	allowAttempt(context.Context, string) (bool, error)
	ping(context.Context) error
	close() error
}

func (s *Service) WithPlatformRoleRefresher(refresher platformRoleRefresher) *Service {
	if s != nil {
		s.roleRefresher = refresher
	}
	return s
}

type zitadelSessionClient interface {
	PasswordSession(context.Context, string, string) (zitadel.Session, error)
	DeleteSession(context.Context, string, string) error
	CreateHumanUser(context.Context, string, string, string) (zitadel.CreatedUser, error)
	CreateHumanUserWithIDPLink(context.Context, string, string, string, zitadel.IDPLink) (zitadel.CreatedUser, error)
	ListAuthorizations(context.Context, zitadel.AuthorizationFilter) ([]zitadel.Authorization, error)
	StartIdentityProviderIntent(context.Context, string, string, string) (string, error)
	RetrieveIdentityProviderIntent(context.Context, string, string) (zitadel.IDPInformation, error)
	AddIDPLink(context.Context, string, zitadel.IDPLink) error
	ListIDPLinks(context.Context, string) ([]zitadel.IDPLink, error)
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
		UserName:    pending.ExternalUserName,
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
	now := time.Now().UTC()
	sessionID, err := randomValue(32)
	if err != nil {
		_ = s.zitadel.DeleteSession(request.Context(), upstreamSession.ID, upstreamSession.Token)
		s.serverError(response, err)
		return
	}
	value := session.Session{
		AssertionSessionID:       sessionID,
		Subject:                  upstreamSession.Subject,
		Entitlements:             append([]string(nil), s.cfg.DefaultEntitlements...),
		PlatformRoles:            s.platformRoles(request.Context(), upstreamSession.Subject),
		PlatformRolesRefreshedAt: now,
		AuthenticationTime:       now,
		AuthenticationMethods:    []string{"pwd"},
		DisplayName:              firstNonEmpty(upstreamSession.DisplayName, upstreamSession.LoginName),
		PreferredUsername:        upstreamSession.LoginName,
		UpstreamSessionID:        upstreamSession.ID,
		UpstreamSessionToken:     upstreamSession.Token,
		CreatedAt:                now,
		LastSeenAt:               now,
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
		AssertionSessionID:       sessionID,
		Subject:                  claims.Subject,
		Entitlements:             append([]string(nil), s.cfg.DefaultEntitlements...),
		PlatformRoles:            s.platformRoles(request.Context(), claims.Subject),
		PlatformRolesRefreshedAt: now,
		AuthenticationTime:       authenticationTime,
		AuthenticationMethods:    []string{"federated"},
		Email:                    claims.Email,
		DisplayName:              firstNonEmpty(claims.Name, claims.PreferredUsername),
		PreferredUsername:        claims.PreferredUsername,
		CreatedAt:                now,
		LastSeenAt:               now,
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
	if request.URL.Query().Get("error") != "" {
		s.redirectOIDCResult(response, request, tx.ReturnTo, "error")
		return
	}
	intentID := firstNonEmpty(request.URL.Query().Get("idp_intent_id"), request.URL.Query().Get("idpIntentId"))
	intentToken := firstNonEmpty(request.URL.Query().Get("idp_intent_token"), request.URL.Query().Get("idpIntentToken"))
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
		ExternalUserName: info.UserName,
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
	now := time.Now().UTC()
	sessionID, err := randomValue(32)
	if err != nil {
		return err
	}
	value := session.Session{
		AssertionSessionID:       sessionID,
		Subject:                  subject,
		Entitlements:             append([]string(nil), s.cfg.DefaultEntitlements...),
		PlatformRoles:            s.platformRoles(ctx, subject),
		PlatformRolesRefreshedAt: now,
		AuthenticationTime:       now,
		AuthenticationMethods:    []string{"federated"},
		Email:                    info.Email,
		DisplayName:              firstNonEmpty(info.DisplayName, info.UserName),
		PreferredUsername:        info.UserName,
		CreatedAt:                now,
		LastSeenAt:               now,
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
	state := request.URL.Query().Get("state")
	tx, err := s.transactions.getLinkTransaction(request.Context(), state)
	if err != nil {
		http.Redirect(response, request, strings.TrimRight(s.cfg.PublicOrigin, "/")+"/account?link_status=error", http.StatusFound)
		return
	}
	_ = s.transactions.deleteLinkTransaction(request.Context(), state)
	if request.URL.Query().Get("error") != "" {
		http.Redirect(response, request, s.linkResultURL(tx.ReturnTo, tx.Provider, "error"), http.StatusFound)
		return
	}
	intentID := firstNonEmpty(request.URL.Query().Get("idp_intent_id"), request.URL.Query().Get("idpIntentId"))
	intentToken := firstNonEmpty(request.URL.Query().Get("idp_intent_token"), request.URL.Query().Get("idpIntentToken"))
	if intentID == "" || intentToken == "" {
		http.Redirect(response, request, s.linkResultURL(tx.ReturnTo, tx.Provider, "error"), http.StatusFound)
		return
	}
	info, err := s.zitadel.RetrieveIdentityProviderIntent(request.Context(), intentID, intentToken)
	expectedID := s.cfg.OIDCProviderIDs[tx.Provider]
	if err != nil || info.IDPID != expectedID || info.UserID == "" {
		http.Redirect(response, request, s.linkResultURL(tx.ReturnTo, tx.Provider, "error"), http.StatusFound)
		return
	}
	if err := s.zitadel.AddIDPLink(request.Context(), tx.Subject, zitadel.IDPLink{IDPID: info.IDPID, UserID: info.UserID, UserName: info.UserName}); err != nil {
		if apiErr, ok := err.(*zitadel.APIError); ok && apiErr.StatusCode == http.StatusConflict {
			http.Redirect(response, request, s.linkResultURL(tx.ReturnTo, tx.Provider, "conflict"), http.StatusFound)
			return
		}
		http.Redirect(response, request, s.linkResultURL(tx.ReturnTo, tx.Provider, "error"), http.StatusFound)
		return
	}
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
		"iamCapabilities": map[string]any{
			"pointsRoleAssignments": map[string]any{
				"read":            slices.Contains(value.PlatformRoles, "opc:system-admin"),
				"write":           slices.Contains(value.PlatformRoles, "opc:system-admin"),
				"manageableRoles": []string{"platform:points-admin", "platform:points-auditor"},
			},
		},
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
	if s.roleRefresher != nil {
		value, err = s.roleRefresher.Refresh(request.Context(), cookie.Value, value)
		if err != nil {
			return session.Session{}, "", err
		}
		if !value.RevokedAt.IsZero() || now.Sub(value.LastSeenAt) > s.cfg.IdleTTL || now.Sub(value.CreatedAt) > s.cfg.AbsoluteTTL {
			return session.Session{}, "", session.ErrNotFound
		}
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
	lookupContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	authorizations, err := s.zitadel.ListAuthorizations(lookupContext, zitadel.AuthorizationFilter{
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
