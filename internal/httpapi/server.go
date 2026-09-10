package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/shiguanglab/auth-service/internal/authorize"
	"github.com/shiguanglab/auth-service/internal/identity"
	"github.com/shiguanglab/auth-service/internal/localidentity"
	loginservice "github.com/shiguanglab/auth-service/internal/login"
	oauthservice "github.com/shiguanglab/auth-service/internal/oauth"
	orgservice "github.com/shiguanglab/auth-service/internal/orgs"
	"github.com/shiguanglab/auth-service/internal/platformroleadmin"
	"github.com/shiguanglab/auth-service/internal/session"
)

const (
	gatewayTokenHeader       = "X-SG-Gateway-Token"
	identityHeader           = "X-SG-Identity"
	maxAuthorizeRequestBytes = 64 << 10
)

type ReadinessCheck func(context.Context) error

type Server struct {
	decision         *authorize.Service
	signer           *identity.Signer
	gatewayToken     [32]byte
	readiness        ReadinessCheck
	logger           *slog.Logger
	login            *loginservice.Service
	orgs             *orgservice.Service
	roleAdmin        *platformroleadmin.Service
	productRoleAdmin *platformroleadmin.Service
	localIdentity    *localidentity.Service
	localBrokers     map[string]LocalBrokerPolicy
	oauth            *oauthservice.Handler
}

type LocalBrokerPolicy struct {
	PublicOrigin         string
	ProductID            string
	Audience             string
	RequiredEntitlements []string
	BrokerTTL            time.Duration
	IdentityTTL          time.Duration
}

func (s *Server) WithLocalIdentity(service *localidentity.Service) *Server {
	s.localIdentity = service
	return s
}

func (s *Server) WithLocalBroker(policy LocalBrokerPolicy) *Server {
	policy.RequiredEntitlements = append([]string(nil), policy.RequiredEntitlements...)
	if s.localBrokers == nil {
		s.localBrokers = make(map[string]LocalBrokerPolicy)
	}
	s.localBrokers[policy.ProductID] = policy
	return s
}

// WithPlatformRoleAdmin mounts the narrowly-scoped Points IAM role API. The
// service itself remains fail-closed when no production writer is configured.
func (s *Server) WithPlatformRoleAdmin(service *platformroleadmin.Service) *Server {
	s.roleAdmin = service
	return s
}

func (s *Server) WithProductRoleAdmin(service *platformroleadmin.Service) *Server {
	s.productRoleAdmin = service
	return s
}

// WithOrganizations attaches the organization domain service. Routes are only
// mounted when both the login service and this service are configured.
func (s *Server) WithOrganizations(orgs *orgservice.Service) *Server {
	s.orgs = orgs
	return s
}

// WithOAuth attaches the OAuth 2.0 authorization server. Routes stay unmounted
// until a handler is supplied, so existing deployments are unaffected.
func (s *Server) WithOAuth(handler *oauthservice.Handler) *Server {
	s.oauth = handler
	return s
}

func NewServer(
	decision *authorize.Service,
	signer *identity.Signer,
	gatewayToken string,
	readiness ReadinessCheck,
	logger *slog.Logger,
	loginServices ...*loginservice.Service,
) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	if readiness == nil {
		readiness = func(context.Context) error { return nil }
	}
	server := &Server{
		decision:     decision,
		signer:       signer,
		gatewayToken: sha256.Sum256([]byte(gatewayToken)),
		readiness:    readiness,
		logger:       logger,
	}
	if len(loginServices) > 0 {
		server.login = loginServices[0]
	}
	return server
}

func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Get("/health/live", writeOK)
	router.Get("/health/ready", s.handleReady)
	router.Get("/.well-known/jwks.json", s.handleJWKS)
	// The OAuth 2.0 authorization server is intentionally mounted outside the
	// gateway middleware: a native client cannot present the shared gateway
	// token. These endpoints protect themselves with PKCE, strict redirect URI
	// validation and the user's own session cookie.
	if s.oauth != nil {
		router.Get("/.well-known/oauth-authorization-server", s.oauth.Metadata)
		router.Get("/oauth/authorize", s.oauth.Authorize)
		router.Post("/oauth/authorize", s.oauth.ConsentSubmit)
		router.Post("/oauth/token", s.oauth.Token)
		router.Post("/oauth/revoke", s.oauth.Revoke)
	}
	router.With(s.authenticateGateway).Get("/v1/forward-auth", s.handleForwardAuth)
	router.With(s.authenticateGateway).Post("/v1/authorize", s.handleAuthorize)
	// The console host uses this same-origin exchange to obtain the
	// audience-bound assertion for the model-gateway micro-frontend.  The
	// product and audience are intentionally fixed here; callers cannot mint a
	// token for an arbitrary service.
	router.With(s.authenticateGateway).Get("/api/auth/identity-token", s.handleIdentityToken)
	if s.localIdentity != nil {
		router.Group(func(local chi.Router) {
			local.Use(s.authenticateGateway)
			local.Get("/login", s.localIdentity.LoginPage)
			local.Post("/api/auth/local/login", s.localIdentity.Login)
			local.Get("/api/auth/session", s.localIdentity.Session)
			local.Post("/api/auth/logout", s.localIdentity.Logout)
			if s.roleAdmin != nil {
				local.Post("/api/auth/iam/points-role-assignments/search", s.roleAdmin.SearchHandler)
				local.Post("/api/auth/iam/points-role-assignments/resolve", s.roleAdmin.ResolveHandler)
				local.Put("/api/auth/iam/points-role-assignments/{userID}", s.roleAdmin.UpdateHandler)
			}
			if s.productRoleAdmin != nil {
				local.Get("/api/auth/portal/access", s.productRoleAdmin.PortalAccessHandler)
				local.Post("/api/auth/iam/product-role-assignments/search", s.productRoleAdmin.SearchHandler)
				local.Post("/api/auth/iam/product-role-assignments/resolve", s.productRoleAdmin.ResolveHandler)
				local.Put("/api/auth/iam/product-role-assignments/{userID}", s.productRoleAdmin.UpdateHandler)
			}
			local.Post("/api/auth/local/provider/fail-next", s.localIdentity.FailNextProviderWrite)
			local.Get("/api/auth/local/iam-commands", s.localIdentity.ListCommands)
			local.Post("/api/auth/local/iam-commands/{operationID}/retry", s.localIdentity.RetryCommand)
		})
		router.Post("/v1/identity/users/search", s.localIdentity.SearchIdentityUsers)
		router.Post("/v1/identity/users/resolve", s.localIdentity.ResolveIdentityUser)
	}
	if s.login != nil {
		router.Group(func(auth chi.Router) {
			auth.Use(s.authenticateGateway)
			auth.Get("/api/auth/providers/feishu/authorize", s.login.FeishuAuthorize)
			auth.Post("/api/auth/providers/feishu/token", s.login.FeishuToken)
			auth.Get("/api/auth/providers/feishu/userinfo", s.login.FeishuUserInfo)
			auth.Get("/api/auth/federated/start", s.login.Start)
			auth.Post("/api/auth/login/context", s.login.Context)
			auth.Post("/api/auth/login/password", s.login.Password)
			auth.Post("/api/auth/register/context", s.login.RegistrationContext)
			auth.Post("/api/auth/register", s.login.Register)
			auth.Get("/api/auth/register/provider", s.login.Start)
			auth.Post("/api/auth/register/federated/context", s.login.FederatedRegistrationContext)
			auth.Post("/api/auth/register/federated", s.login.RegisterFederated)
			auth.Get("/api/auth/oidc/callback", s.login.Callback)
			auth.Get("/api/auth/idp-links/start", s.login.StartIDPLink)
			auth.Get("/api/auth/idp-links/callback", s.login.IDPLinkCallback)
			auth.Get("/api/auth/idp-links", s.login.ListIDPLinks)
			auth.Get("/api/auth/session", s.login.Session)
			auth.Get("/api/account/profile", s.login.Profile)
			auth.Patch("/api/account/profile", s.login.UpdateProfile)
			auth.Post("/api/account/avatar", s.login.UploadAvatar)
			auth.Post("/api/auth/logout", s.login.Logout)
			if len(s.localBrokers) > 0 {
				auth.Post("/api/auth/local-broker", s.handleLocalBrokerLogin)
				auth.Post("/api/auth/local-broker/refresh", s.handleLocalBrokerRefresh)
			}
			if s.roleAdmin != nil {
				auth.Post("/api/auth/iam/points-role-assignments/search", s.roleAdmin.SearchHandler)
				auth.Post("/api/auth/iam/points-role-assignments/resolve", s.roleAdmin.ResolveHandler)
				auth.Put("/api/auth/iam/points-role-assignments/{userID}", s.roleAdmin.UpdateHandler)
			}
			if s.productRoleAdmin != nil {
				auth.Get("/api/auth/portal/access", s.productRoleAdmin.PortalAccessHandler)
				auth.Post("/api/auth/iam/product-role-assignments/search", s.productRoleAdmin.SearchHandler)
				auth.Post("/api/auth/iam/product-role-assignments/resolve", s.productRoleAdmin.ResolveHandler)
				auth.Put("/api/auth/iam/product-role-assignments/{userID}", s.productRoleAdmin.UpdateHandler)
			}
			if s.orgs != nil {
				auth.Post("/api/auth/context", s.orgs.SwitchContextHandler)
				auth.Post("/api/account/orgs", s.orgs.CreateOrganizationHandler)
				auth.Get("/api/account/orgs", s.orgs.ListMyOrganizationsHandler)
				auth.Get("/api/account/orgs/{orgID}/members", s.orgs.ListMembersHandler)
				auth.Post("/api/account/orgs/{orgID}/members", s.orgs.AddMemberHandler)
				auth.Patch("/api/account/orgs/{orgID}/members/{userID}", s.orgs.UpdateMemberHandler)
				auth.Delete("/api/account/orgs/{orgID}/members/{userID}", s.orgs.RemoveMemberHandler)
			}
		})
	}
	if s.orgs != nil {
		router.Group(func(pointsIdentity chi.Router) {
			pointsIdentity.Use(s.orgs.RequirePointsIdentityServiceToken)
			pointsIdentity.Post("/v1/identity/users/search", s.orgs.SearchUsersHandler)
			pointsIdentity.Post("/v1/identity/users/resolve", s.orgs.ResolveUserHandler)
		})
		router.Group(func(identityAPI chi.Router) {
			identityAPI.Use(s.orgs.RequireIdentityAPIToken)
			identityAPI.Post("/v1/identity/users/batch-get", s.orgs.BatchGetUsersHandler)
			identityAPI.Get("/v1/identity/orgs/{orgID}/members", s.orgs.ServiceListMembersHandler)
		})
	}
	return router
}

func (s *Server) handleLocalBrokerLogin(response http.ResponseWriter, request *http.Request) {
	if !s.validLocalBrokerOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	var input struct {
		LoginName string `json:"loginName"`
		Password  string `json:"password"`
		ProductID string `json:"productId"`
	}
	if err := decodeBrokerJSON(response, request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	policy, ok := s.localBrokers[strings.TrimSpace(input.ProductID)]
	if !ok {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_product"})
		return
	}
	if request.Header.Get("Origin") != policy.PublicOrigin {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	brokerToken, value, err := s.login.CreateLocalBroker(
		request.Context(),
		brokerClientKey(request),
		input.LoginName,
		input.Password,
		policy.ProductID,
		policy.BrokerTTL,
	)
	if err != nil {
		switch {
		case errors.Is(err, loginservice.ErrBrokerInvalidCredentials):
			writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		case errors.Is(err, loginservice.ErrBrokerRateLimited):
			writeJSON(response, http.StatusTooManyRequests, map[string]string{"error": "try_again_later"})
		default:
			s.logger.Error("create local broker", "error", err)
			writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "broker_unavailable"})
		}
		return
	}
	s.writeLocalBrokerResponse(response, request, brokerToken, value, policy)
}

func (s *Server) handleLocalBrokerRefresh(response http.ResponseWriter, request *http.Request) {
	if !s.validLocalBrokerOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	brokerToken := bearerToken(request.Header.Get("Authorization"))
	value, err := s.login.ResolveLocalBroker(request.Context(), brokerToken)
	if err != nil {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "broker_invalid"})
		return
	}
	policy, ok := s.localBrokers[value.BrokerProductID]
	if !ok {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "broker_invalid"})
		return
	}
	if request.Header.Get("Origin") != policy.PublicOrigin {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	s.writeLocalBrokerResponse(response, request, brokerToken, value, policy)
}

func (s *Server) writeLocalBrokerResponse(
	response http.ResponseWriter,
	request *http.Request,
	brokerToken string,
	value session.Session,
	policy LocalBrokerPolicy,
) {
	decision := s.decision.DecideBroker(request.Context(), brokerToken, authorize.Request{
		ProductID:            policy.ProductID,
		Audience:             policy.Audience,
		RequiredEntitlements: policy.RequiredEntitlements,
	})
	if !decision.Allow {
		writeJSON(response, decision.Status, map[string]string{"error": decision.Reason})
		return
	}
	var organization any
	if value.OrganizationID != "" {
		organization = map[string]string{"id": value.OrganizationID, "name": value.OrganizationName}
	}
	now := time.Now().UTC()
	writeJSON(response, http.StatusOK, map[string]any{
		"brokerToken":       brokerToken,
		"brokerExpiresAt":   value.CredentialExpiresAt.Format(time.RFC3339Nano),
		"identityToken":     decision.IdentityToken,
		"identityExpiresAt": now.Add(policy.IdentityTTL).Format(time.RFC3339Nano),
		"session": map[string]any{
			"authenticated":     true,
			"subject":           value.Subject,
			"displayName":       value.DisplayName,
			"email":             value.Email,
			"preferredUsername": value.PreferredUsername,
			"entitlements":      value.Entitlements,
			"organization":      organization,
			"roles":             value.Roles,
			"platformRoles":     value.PlatformRoles,
		},
	})
}

func (s *Server) validLocalBrokerOrigin(request *http.Request) bool {
	origin := request.Header.Get("Origin")
	for _, policy := range s.localBrokers {
		if origin == policy.PublicOrigin {
			return true
		}
	}
	return false
}

func decodeBrokerJSON(response http.ResponseWriter, request *http.Request, value any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 4<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("one JSON value is required")
	}
	return nil
}

func brokerClientKey(request *http.Request) string {
	if forwarded := strings.TrimSpace(strings.Split(request.Header.Get("X-Forwarded-For"), ",")[0]); forwarded != "" {
		return forwarded
	}
	return request.RemoteAddr
}

func bearerToken(value string) string {
	scheme, token, ok := strings.Cut(strings.TrimSpace(value), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

func (s *Server) handleForwardAuth(response http.ResponseWriter, request *http.Request) {
	input := authorize.Request{
		RequestID:            middleware.GetReqID(request.Context()),
		Method:               request.Header.Get("X-Forwarded-Method"),
		Scheme:               request.Header.Get("X-Forwarded-Proto"),
		Host:                 forwardedHost(request),
		Path:                 request.Header.Get("X-Forwarded-Uri"),
		ClientIP:             request.Header.Get("X-Forwarded-For"),
		Cookie:               request.Header.Get("Cookie"),
		Authorization:        request.Header.Get("Authorization"),
		Origin:               request.Header.Get("Origin"),
		Accept:               request.Header.Get("Accept"),
		ProductID:            request.Header.Get("X-SG-Product-ID"),
		Audience:             request.Header.Get("X-SG-Audience"),
		RequiredEntitlements: splitCSV(request.Header.Get("X-SG-Required-Entitlements")),
	}
	decision := s.decide(request.Context(), input)

	for _, cookie := range decision.SetCookies {
		response.Header().Add("Set-Cookie", cookie)
	}
	if decision.Location != "" {
		response.Header().Set("Location", decision.Location)
	}
	if decision.Allow {
		response.Header().Set(identityHeader, decision.IdentityToken)
		response.WriteHeader(http.StatusOK)
		return
	}
	writeJSON(response, decision.Status, map[string]string{"error": decision.Reason})
}

func (s *Server) handleIdentityToken(response http.ResponseWriter, request *http.Request) {
	input := authorize.Request{
		RequestID: middleware.GetReqID(request.Context()),
		Method:    http.MethodGet,
		Scheme:    request.Header.Get("X-Forwarded-Proto"),
		Host:      forwardedHost(request),
		Path:      "/api/auth/identity-token",
		ClientIP:  request.Header.Get("X-Forwarded-For"),
		Cookie:    request.Header.Get("Cookie"),
		Origin:    request.Header.Get("Origin"),
		Accept:    request.Header.Get("Accept"),
		ProductID: "model-gateway",
		Audience:  "model-gateway-bff",
	}
	decision := s.decide(request.Context(), input)
	for _, cookie := range decision.SetCookies {
		response.Header().Add("Set-Cookie", cookie)
	}
	if !decision.Allow {
		writeJSON(response, decision.Status, map[string]string{"error": decision.Reason})
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	writeJSON(response, http.StatusOK, map[string]string{"identityToken": decision.IdentityToken})
}

func (s *Server) handleAuthorize(response http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(response, request.Body, maxAuthorizeRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()

	var input authorize.Request
	if err := decoder.Decode(&input); err != nil {
		s.writeInvalidAuthorizeRequest(response, err)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		s.writeInvalidAuthorizeRequest(response, err)
		return
	}
	if input.RequestID == "" {
		input.RequestID = middleware.GetReqID(request.Context())
	}
	writeJSON(response, http.StatusOK, s.decide(request.Context(), input))
}

func (s *Server) decide(ctx context.Context, input authorize.Request) authorize.Response {
	decision := s.decision.Decide(ctx, input)
	if !decision.Allow &&
		decision.Status == http.StatusUnauthorized &&
		(input.Method == http.MethodGet || input.Method == http.MethodHead) &&
		strings.Contains(strings.ToLower(input.Accept), "text/html") {
		returnTo := input.Path
		if returnTo == "" || !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") {
			returnTo = "/"
		}
		decision.Status = http.StatusFound
		if s.login != nil {
			decision.Location = s.login.LoginLocation(input.Scheme, input.Host, returnTo)
		} else {
			decision.Location = "/login?return_to=" + url.QueryEscape(returnTo)
		}
	}
	s.logger.Info("authorization decision",
		"request_id", input.RequestID,
		"product_id", input.ProductID,
		"host", input.Host,
		"path", input.Path,
		"allow", decision.Allow,
		"status", decision.Status,
		"reason", decision.Reason,
	)
	return decision
}

func (s *Server) writeInvalidAuthorizeRequest(response http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		status = http.StatusRequestEntityTooLarge
	}
	writeJSON(response, status, authorize.Response{
		Allow:  false,
		Status: status,
		Reason: "invalid_request",
	})
}

func (s *Server) handleReady(response http.ResponseWriter, request *http.Request) {
	if err := s.readiness(request.Context()); err != nil {
		s.logger.Warn("readiness check failed", "error", err)
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeOK(response, request)
}

func (s *Server) handleJWKS(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(response, http.StatusOK, s.signer.JWKS())
}

func (s *Server) authenticateGateway(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		actual := sha256.Sum256([]byte(request.Header.Get(gatewayTokenHeader)))
		if subtle.ConstantTimeCompare(actual[:], s.gatewayToken[:]) != 1 {
			writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(response, request)
	})
}

func forwardedHost(request *http.Request) string {
	if value := request.Header.Get("X-Forwarded-Host"); value != "" {
		return value
	}
	return request.Host
}

func splitCSV(raw string) []string {
	var values []string
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func writeOK(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	if response.Header().Get("Cache-Control") == "" {
		response.Header().Set("Cache-Control", "no-store")
	}
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		slog.Default().Error("write JSON response", "error", err)
	}
}
