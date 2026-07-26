package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/shiguanglab/auth-service/internal/authorize"
	"github.com/shiguanglab/auth-service/internal/identity"
	loginservice "github.com/shiguanglab/auth-service/internal/login"
	orgservice "github.com/shiguanglab/auth-service/internal/orgs"
)

const (
	gatewayTokenHeader = "X-SG-Gateway-Token"
	identityHeader     = "X-SG-Identity"
)

type ReadinessCheck func(context.Context) error

type Server struct {
	decision     *authorize.Service
	signer       *identity.Signer
	gatewayToken [32]byte
	readiness    ReadinessCheck
	logger       *slog.Logger
	login        *loginservice.Service
	orgs         *orgservice.Service
}

// WithOrganizations attaches the organization domain service. Routes are only
// mounted when both the login service and this service are configured.
func (s *Server) WithOrganizations(orgs *orgservice.Service) *Server {
	s.orgs = orgs
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
	router.With(s.authenticateGateway).Get("/v1/forward-auth", s.handleForwardAuth)
	if s.login != nil {
		router.Group(func(auth chi.Router) {
			auth.Use(s.authenticateGateway)
			auth.Get("/api/auth/federated/start", s.login.Start)
			auth.Post("/api/auth/login/context", s.login.Context)
			auth.Post("/api/auth/login/password", s.login.Password)
			auth.Post("/api/auth/register/context", s.login.RegistrationContext)
			auth.Post("/api/auth/register", s.login.Register)
			auth.Get("/api/auth/register/provider", s.login.Start)
			auth.Get("/api/auth/oidc/callback", s.login.Callback)
			auth.Get("/api/auth/session", s.login.Session)
			auth.Post("/api/auth/logout", s.login.Logout)
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
		router.Group(func(identityAPI chi.Router) {
			identityAPI.Use(s.orgs.RequireIdentityAPIToken)
			identityAPI.Post("/v1/identity/users/batch-get", s.orgs.BatchGetUsersHandler)
			identityAPI.Get("/v1/identity/orgs/{orgID}/members", s.orgs.ServiceListMembersHandler)
		})
	}
	return router
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
	decision := s.decision.Decide(request.Context(), input)
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
