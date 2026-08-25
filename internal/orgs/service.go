// Package orgs implements the platform organization domain: organization
// creation, membership management, the personal/organization context switch,
// and the service-to-service identity query facade used by products.
//
// Organizations live in ZITADEL. A business organization is a ZITADEL
// organization that received a grant for the platform project; membership is
// a ZITADEL authorization (user grant) carrying the org:* role keys. This
// service holds no organization state of its own.
package orgs

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/shiguanglab/auth-service/internal/config"
	"github.com/shiguanglab/auth-service/internal/session"
	"github.com/shiguanglab/auth-service/internal/zitadel"
)

const (
	RoleAdmin  = "org:admin"
	RoleMember = "org:member"
	RoleViewer = "org:viewer"
)

var (
	memberRoles     = []string{RoleAdmin, RoleMember, RoleViewer}
	orgNamePattern  = regexp.MustCompile(`^\S.{0,58}\S$`)
	errNotAuthentic = errors.New("request is not authenticated")
)

type directoryClient interface {
	CreateOrganization(context.Context, string) (zitadel.Organization, error)
	SearchOrganizationsByIDs(context.Context, []string) ([]zitadel.Organization, error)
	EnsureProjectRole(context.Context, string, string, string) error
	EnsureProjectGrant(context.Context, string, string, []string) error
	CreateAuthorization(context.Context, string, string, string, []string) (string, error)
	UpdateAuthorization(context.Context, string, []string) error
	DeleteAuthorization(context.Context, string) error
	ListAuthorizations(context.Context, zitadel.AuthorizationFilter) ([]zitadel.Authorization, error)
	GetUserByLoginName(context.Context, string) (zitadel.User, error)
	SearchUsersByIDs(context.Context, []string) ([]zitadel.User, error)
	SearchUsers(context.Context, string, int) ([]zitadel.User, error)
}

type sessionResolver interface {
	ResolveSession(*http.Request) (session.Session, string, error)
}

type Service struct {
	cfg          config.Config
	sessions     session.Store
	resolver     sessionResolver
	zitadel      directoryClient
	logger       *slog.Logger
	prepared     bool
	searchMu     sync.Mutex
	searchWindow time.Time
	searchCount  int
	searchLimit  int
	searchNow    func() time.Time
}

func NewService(cfg config.Config, sessions session.Store, resolver sessionResolver, directory directoryClient, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		cfg:         cfg,
		sessions:    sessions,
		resolver:    resolver,
		zitadel:     directory,
		logger:      logger,
		searchLimit: 30,
		searchNow:   time.Now,
	}
}

// ensureProjectRoles lazily creates the platform project roles once per
// process. Creation is idempotent on the ZITADEL side.
func (s *Service) ensureProjectRoles(ctx context.Context) error {
	if s.prepared {
		return nil
	}
	displayNames := map[string]string{
		RoleAdmin:  "Organization Admin",
		RoleMember: "Organization Member",
		RoleViewer: "Organization Viewer",
	}
	for _, role := range memberRoles {
		if err := s.zitadel.EnsureProjectRole(ctx, s.cfg.ZitadelProjectID, role, displayNames[role]); err != nil {
			return err
		}
	}
	s.prepared = true
	return nil
}

// ---- browser-facing organization API -------------------------------------

func (s *Service) CreateOrganizationHandler(response http.ResponseWriter, request *http.Request) {
	current, _, err := s.authenticated(response, request, true)
	if err != nil {
		return
	}
	var input struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	input.Name = strings.TrimSpace(input.Name)
	if !orgNamePattern.MatchString(input.Name) {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_organization_name"})
		return
	}
	if err := s.ensureProjectRoles(request.Context()); err != nil {
		s.serverError(response, err)
		return
	}
	organization, err := s.zitadel.CreateOrganization(request.Context(), input.Name)
	if err != nil {
		var apiError *zitadel.APIError
		if errors.As(err, &apiError) && apiError.StatusCode == http.StatusConflict {
			writeJSON(response, http.StatusConflict, map[string]string{"error": "organization_exists"})
			return
		}
		s.serverError(response, err)
		return
	}
	if err := s.zitadel.EnsureProjectGrant(request.Context(), s.cfg.ZitadelProjectID, organization.ID, memberRoles); err != nil {
		s.serverError(response, err)
		return
	}
	if _, err := s.zitadel.CreateAuthorization(
		request.Context(), current.Subject, s.cfg.ZitadelProjectID, organization.ID, []string{RoleAdmin},
	); err != nil {
		s.serverError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, map[string]any{
		"id":    organization.ID,
		"name":  organization.Name,
		"roles": []string{RoleAdmin},
	})
}

func (s *Service) ListMyOrganizationsHandler(response http.ResponseWriter, request *http.Request) {
	current, _, err := s.authenticated(response, request, false)
	if err != nil {
		return
	}
	memberships, err := s.membershipsOf(request.Context(), current.Subject)
	if err != nil {
		s.serverError(response, err)
		return
	}
	ids := make([]string, 0, len(memberships))
	for _, membership := range memberships {
		ids = append(ids, membership.OrganizationID)
	}
	names := map[string]string{}
	if organizations, err := s.zitadel.SearchOrganizationsByIDs(request.Context(), ids); err == nil {
		for _, organization := range organizations {
			names[organization.ID] = organization.Name
		}
	} else {
		s.logger.Warn("resolve organization names", "error", err)
	}
	result := make([]map[string]any, 0, len(memberships))
	for _, membership := range memberships {
		result = append(result, map[string]any{
			"id":    membership.OrganizationID,
			"name":  names[membership.OrganizationID],
			"roles": membership.Roles,
		})
	}
	writeJSON(response, http.StatusOK, map[string]any{"organizations": result})
}

func (s *Service) ListMembersHandler(response http.ResponseWriter, request *http.Request) {
	current, _, err := s.authenticated(response, request, false)
	if err != nil {
		return
	}
	orgID := chi.URLParam(request, "orgID")
	if _, err := s.requireMembership(request.Context(), current.Subject, orgID, false); err != nil {
		s.membershipError(response, err)
		return
	}
	members, err := s.membersOf(request.Context(), orgID)
	if err != nil {
		s.serverError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"members": members})
}

func (s *Service) AddMemberHandler(response http.ResponseWriter, request *http.Request) {
	current, _, err := s.authenticated(response, request, true)
	if err != nil {
		return
	}
	orgID := chi.URLParam(request, "orgID")
	if _, err := s.requireMembership(request.Context(), current.Subject, orgID, true); err != nil {
		s.membershipError(response, err)
		return
	}
	var input struct {
		LoginName string `json:"loginName"`
		Role      string `json:"role"`
	}
	if err := decodeJSON(request, &input); err != nil || !validRole(input.Role) || strings.TrimSpace(input.LoginName) == "" {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	user, err := s.zitadel.GetUserByLoginName(request.Context(), strings.TrimSpace(input.LoginName))
	if err != nil {
		var apiError *zitadel.APIError
		if errors.As(err, &apiError) && apiError.StatusCode == http.StatusNotFound {
			writeJSON(response, http.StatusNotFound, map[string]string{"error": "user_not_found"})
			return
		}
		s.serverError(response, err)
		return
	}
	if !activeUserState(user.State) {
		writeJSON(response, http.StatusNotFound, map[string]string{"error": "user_not_found"})
		return
	}
	if _, err := s.zitadel.CreateAuthorization(
		request.Context(), user.ID, s.cfg.ZitadelProjectID, orgID, []string{input.Role},
	); err != nil {
		var apiError *zitadel.APIError
		if errors.As(err, &apiError) && apiError.StatusCode == http.StatusConflict {
			writeJSON(response, http.StatusConflict, map[string]string{"error": "member_exists"})
			return
		}
		s.serverError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, map[string]any{
		"userId":      user.ID,
		"loginName":   user.LoginName,
		"displayName": user.DisplayName,
		"roles":       []string{input.Role},
	})
}

func (s *Service) UpdateMemberHandler(response http.ResponseWriter, request *http.Request) {
	current, _, err := s.authenticated(response, request, true)
	if err != nil {
		return
	}
	orgID := chi.URLParam(request, "orgID")
	userID := chi.URLParam(request, "userID")
	if _, err := s.requireMembership(request.Context(), current.Subject, orgID, true); err != nil {
		s.membershipError(response, err)
		return
	}
	var input struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(request, &input); err != nil || !validRole(input.Role) {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	target, err := s.membershipIn(request.Context(), userID, orgID)
	if err != nil {
		s.membershipError(response, err)
		return
	}
	if input.Role != RoleAdmin && containsRole(target.Roles, RoleAdmin) {
		if err := s.assertNotLastAdmin(request.Context(), orgID, userID); err != nil {
			s.membershipError(response, err)
			return
		}
	}
	if err := s.zitadel.UpdateAuthorization(request.Context(), target.ID, []string{input.Role}); err != nil {
		s.serverError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"userId": userID, "roles": []string{input.Role}})
}

func (s *Service) RemoveMemberHandler(response http.ResponseWriter, request *http.Request) {
	current, _, err := s.authenticated(response, request, true)
	if err != nil {
		return
	}
	orgID := chi.URLParam(request, "orgID")
	userID := chi.URLParam(request, "userID")
	// Members may leave on their own; removing anyone else requires admin.
	if current.Subject != userID {
		if _, err := s.requireMembership(request.Context(), current.Subject, orgID, true); err != nil {
			s.membershipError(response, err)
			return
		}
	}
	target, err := s.membershipIn(request.Context(), userID, orgID)
	if err != nil {
		s.membershipError(response, err)
		return
	}
	if containsRole(target.Roles, RoleAdmin) {
		if err := s.assertNotLastAdmin(request.Context(), orgID, userID); err != nil {
			s.membershipError(response, err)
			return
		}
	}
	if err := s.zitadel.DeleteAuthorization(request.Context(), target.ID); err != nil {
		s.serverError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

// ---- personal/organization context switch ---------------------------------

func (s *Service) SwitchContextHandler(response http.ResponseWriter, request *http.Request) {
	current, sessionID, err := s.authenticated(response, request, true)
	if err != nil {
		return
	}
	var input struct {
		OrganizationID string `json:"organizationId"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	input.OrganizationID = strings.TrimSpace(input.OrganizationID)

	if input.OrganizationID == "" {
		current.OrganizationID = ""
		current.OrganizationName = ""
		current.Roles = nil
	} else {
		membership, err := s.membershipIn(request.Context(), current.Subject, input.OrganizationID)
		if err != nil {
			s.membershipError(response, err)
			return
		}
		name := ""
		if organizations, err := s.zitadel.SearchOrganizationsByIDs(request.Context(), []string{input.OrganizationID}); err == nil && len(organizations) > 0 {
			name = organizations[0].Name
		}
		current.OrganizationID = input.OrganizationID
		current.OrganizationName = name
		current.Roles = membership.Roles
	}
	current.LastSeenAt = time.Now().UTC()
	if err := s.sessions.Put(request.Context(), sessionID, current); err != nil {
		s.serverError(response, err)
		return
	}
	var organization any
	if current.OrganizationID != "" {
		organization = map[string]string{"id": current.OrganizationID, "name": current.OrganizationName}
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"organization": organization,
		"roles":        current.Roles,
	})
}

// ---- service-to-service identity facade -----------------------------------

// RequireIdentityAPIToken guards the identity facade with a dedicated product
// credential so products never hold the gateway shared token.
func (s *Service) RequireIdentityAPIToken(next http.Handler) http.Handler {
	expected := sha256.Sum256([]byte(s.cfg.IdentityAPIToken))
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		token := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
		actual := sha256.Sum256([]byte(token))
		if s.cfg.IdentityAPIToken == "" || subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
			writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		next.ServeHTTP(response, request)
	})
}

// RequirePointsIdentityServiceToken isolates the Points user picker from the
// general product identity facade and all browser/gateway credentials.
func (s *Service) RequirePointsIdentityServiceToken(next http.Handler) http.Handler {
	expected := sha256.Sum256([]byte(s.cfg.PointsIdentityServiceToken))
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		token := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
		actual := sha256.Sum256([]byte(token))
		if s.cfg.PointsIdentityServiceToken == "" || subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
			writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
			return
		}
		next.ServeHTTP(response, request)
	})
}

func (s *Service) SearchUsersHandler(response http.ResponseWriter, request *http.Request) {
	var input struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	input.Query = strings.TrimSpace(input.Query)
	queryLength := utf8.RuneCountInString(input.Query)
	if queryLength < 3 || queryLength > 64 || input.Limit < 1 || input.Limit > 10 {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if !s.allowUserSearch() {
		writeJSON(response, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	users, err := s.zitadel.SearchUsers(ctx, input.Query, input.Limit)
	cancel()
	if err != nil {
		s.logger.Warn("points identity search unavailable", "error", err)
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "directory_unavailable"})
		return
	}
	result := make([]map[string]any, 0, len(users))
	for _, user := range users {
		if !activeUserState(user.State) {
			continue
		}
		result = append(result, map[string]any{
			"id":          user.ID,
			"loginName":   user.LoginName,
			"displayName": user.DisplayName,
			"state":       user.State,
		})
		if len(result) == input.Limit {
			break
		}
	}
	writeJSON(response, http.StatusOK, map[string]any{"users": result})
}

// ResolveUserHandler performs the exact ACTIVE-user check required after a
// picker selection and before Points persists a new member reference.
func (s *Service) ResolveUserHandler(response http.ResponseWriter, request *http.Request) {
	var input struct {
		UserID string `json:"userId"`
	}
	if err := decodeJSON(request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	input.UserID = strings.TrimSpace(input.UserID)
	if input.UserID == "" || len(input.UserID) > 200 {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if !s.allowUserSearch() {
		writeJSON(response, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	users, err := s.zitadel.SearchUsersByIDs(ctx, []string{input.UserID})
	cancel()
	if err != nil {
		s.logger.Warn("points identity resolve unavailable", "error", err)
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "directory_unavailable"})
		return
	}
	for _, user := range users {
		if user.ID != input.UserID || !activeUserState(user.State) {
			continue
		}
		writeJSON(response, http.StatusOK, map[string]any{"user": map[string]any{
			"id":          user.ID,
			"loginName":   user.LoginName,
			"displayName": user.DisplayName,
			"state":       user.State,
		}})
		return
	}
	writeJSON(response, http.StatusNotFound, map[string]string{"error": "user_not_found"})
}

func (s *Service) allowUserSearch() bool {
	now := s.searchNow().UTC()
	s.searchMu.Lock()
	defer s.searchMu.Unlock()
	if s.searchWindow.IsZero() || now.Sub(s.searchWindow) >= time.Minute || now.Before(s.searchWindow) {
		s.searchWindow = now
		s.searchCount = 0
	}
	if s.searchCount >= s.searchLimit {
		return false
	}
	s.searchCount++
	return true
}

func (s *Service) BatchGetUsersHandler(response http.ResponseWriter, request *http.Request) {
	var input struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(request, &input); err != nil || len(input.IDs) == 0 || len(input.IDs) > 200 {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	users, err := s.zitadel.SearchUsersByIDs(request.Context(), input.IDs)
	if err != nil {
		s.serverError(response, err)
		return
	}
	result := make([]map[string]any, 0, len(users))
	for _, user := range users {
		result = append(result, map[string]any{
			"id":          user.ID,
			"loginName":   user.LoginName,
			"displayName": user.DisplayName,
			"email":       user.Email,
			"state":       user.State,
		})
	}
	writeJSON(response, http.StatusOK, map[string]any{"users": result})
}

func (s *Service) ServiceListMembersHandler(response http.ResponseWriter, request *http.Request) {
	orgID := chi.URLParam(request, "orgID")
	if strings.TrimSpace(orgID) == "" {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	members, err := s.membersOf(request.Context(), orgID)
	if err != nil {
		s.serverError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"members": members})
}

// ---- shared helpers --------------------------------------------------------

var (
	errForbidden = errors.New("caller lacks the required organization role")
	errNotMember = errors.New("user is not a member of the organization")
	errLastAdmin = errors.New("organization requires at least one admin")
)

func (s *Service) authenticated(response http.ResponseWriter, request *http.Request, mutating bool) (session.Session, string, error) {
	if mutating && !s.validOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return session.Session{}, "", errNotAuthentic
	}
	current, sessionID, err := s.resolver.ResolveSession(request)
	if err != nil {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return session.Session{}, "", errNotAuthentic
	}
	return current, sessionID, nil
}

func (s *Service) validOrigin(request *http.Request) bool {
	origin := request.Header.Get("Origin")
	if origin == s.cfg.PublicOrigin {
		return true
	}
	for _, allowed := range s.cfg.AllowedReturnOrigins {
		if origin == strings.TrimRight(allowed, "/") {
			return true
		}
	}
	return false
}

func (s *Service) membershipsOf(ctx context.Context, userID string) ([]zitadel.Authorization, error) {
	authorizations, err := s.zitadel.ListAuthorizations(ctx, zitadel.AuthorizationFilter{
		UserID:     userID,
		ProjectID:  s.cfg.ZitadelProjectID,
		ActiveOnly: true,
	})
	if err != nil {
		return nil, err
	}
	// Authorizations on the platform organization carry system-level roles
	// (for example system-admin). The platform organization is identity
	// plumbing, not a business tenant: it must never surface as a switchable
	// organization.
	memberships := authorizations[:0]
	for _, authorization := range authorizations {
		if authorization.OrganizationID == s.cfg.ZitadelOrganizationID {
			continue
		}
		memberships = append(memberships, authorization)
	}
	return memberships, nil
}

func (s *Service) membershipIn(ctx context.Context, userID, orgID string) (zitadel.Authorization, error) {
	// The platform organization is not a business tenant (see membershipsOf).
	if strings.TrimSpace(orgID) == "" || orgID == s.cfg.ZitadelOrganizationID {
		return zitadel.Authorization{}, errNotMember
	}
	memberships, err := s.zitadel.ListAuthorizations(ctx, zitadel.AuthorizationFilter{
		UserID:         userID,
		OrganizationID: orgID,
		ProjectID:      s.cfg.ZitadelProjectID,
		ActiveOnly:     true,
	})
	if err != nil {
		return zitadel.Authorization{}, err
	}
	if len(memberships) == 0 {
		return zitadel.Authorization{}, errNotMember
	}
	return memberships[0], nil
}

func (s *Service) requireMembership(ctx context.Context, userID, orgID string, admin bool) (zitadel.Authorization, error) {
	membership, err := s.membershipIn(ctx, userID, orgID)
	if err != nil {
		return zitadel.Authorization{}, err
	}
	if admin && !containsRole(membership.Roles, RoleAdmin) {
		return zitadel.Authorization{}, errForbidden
	}
	return membership, nil
}

func (s *Service) membersOf(ctx context.Context, orgID string) ([]map[string]any, error) {
	authorizations, err := s.zitadel.ListAuthorizations(ctx, zitadel.AuthorizationFilter{
		OrganizationID: orgID,
		ProjectID:      s.cfg.ZitadelProjectID,
		ActiveOnly:     true,
	})
	if err != nil {
		return nil, err
	}
	members := make([]map[string]any, 0, len(authorizations))
	for _, authorization := range authorizations {
		members = append(members, map[string]any{
			"userId":      authorization.UserID,
			"loginName":   authorization.LoginName,
			"displayName": authorization.DisplayName,
			"roles":       authorization.Roles,
		})
	}
	return members, nil
}

func (s *Service) assertNotLastAdmin(ctx context.Context, orgID, exceptUserID string) error {
	authorizations, err := s.zitadel.ListAuthorizations(ctx, zitadel.AuthorizationFilter{
		OrganizationID: orgID,
		ProjectID:      s.cfg.ZitadelProjectID,
		ActiveOnly:     true,
	})
	if err != nil {
		return err
	}
	for _, authorization := range authorizations {
		if authorization.UserID != exceptUserID && containsRole(authorization.Roles, RoleAdmin) {
			return nil
		}
	}
	return errLastAdmin
}

func (s *Service) membershipError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errNotMember):
		writeJSON(response, http.StatusNotFound, map[string]string{"error": "not_a_member"})
	case errors.Is(err, errForbidden):
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "requires_org_admin"})
	case errors.Is(err, errLastAdmin):
		writeJSON(response, http.StatusConflict, map[string]string{"error": "last_admin"})
	default:
		s.serverError(response, err)
	}
}

func (s *Service) serverError(response http.ResponseWriter, err error) {
	s.logger.Error("organization request failed", "error", err)
	writeJSON(response, http.StatusInternalServerError, map[string]string{"error": "temporarily_unavailable"})
}

func validRole(role string) bool {
	return containsRole(memberRoles, role)
}

func containsRole(roles []string, role string) bool {
	for _, candidate := range roles {
		if candidate == role {
			return true
		}
	}
	return false
}

func decodeJSON(request *http.Request, value any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(nil, request.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request body must contain exactly one JSON value")
	}
	return nil
}

func activeUserState(state string) bool {
	return state == "USER_STATE_ACTIVE" || state == "STATE_ACTIVE"
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
