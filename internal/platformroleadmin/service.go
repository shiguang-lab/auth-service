// Package platformroleadmin owns the IAM contract for assigning allowlisted
// platform product roles. Product-internal resource permissions remain in each
// product service.
package platformroleadmin

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/shiguanglab/auth-service/internal/session"
)

const (
	IAMManagerRole      = "opc:system-admin"
	PointsAdminRole     = "platform:points-admin"
	PointsAuditorRole   = "platform:points-auditor"
	HuiguangUserRole    = "huiguang:user"
	HuiguangGrayRole    = "huiguang:gray-creator"
	HuiguangOpsRole     = "huiguang:ops-admin"
	YingguangUserRole   = "yingguang:user"
	YingguangOpsRole    = "yingguang:ops-admin"
	LingguangUserRole   = "lingguang:consumer"
	LingguangDevRole    = "lingguang:developer"
	LingguangReviewRole = "lingguang:reviewer"
	LingguangAdminRole  = "lingguang:platform-admin"
	maxRequestBytes     = 16 << 10
)

var (
	ManageableRoles        = []string{PointsAdminRole, PointsAuditorRole}
	ProductManageableRoles = []string{
		HuiguangUserRole, HuiguangGrayRole, HuiguangOpsRole,
		YingguangUserRole, YingguangOpsRole,
		LingguangUserRole, LingguangDevRole, LingguangReviewRole, LingguangAdminRole,
		PointsAuditorRole, PointsAdminRole,
	}
	ErrUnavailable = errors.New("IAM role directory is unavailable")
)

type User struct {
	ID          string   `json:"id"`
	LoginName   string   `json:"loginName"`
	DisplayName string   `json:"displayName"`
	State       string   `json:"state"`
	Roles       []string `json:"roles"`
}

type Directory interface {
	SearchUsers(context.Context, string, int) ([]User, error)
	GetUser(context.Context, string) (User, error)
}

// RoleChange is the durable command passed to the IAM mutation boundary.
// Implementations must persist it before calling the identity provider and
// record the outcome so interrupted commands can be reconciled safely.
type RoleChange struct {
	IdempotencyKey string
	ActorSubject   string
	TargetUserID   string
	BeforeRoles    []string
	AfterRoles     []string
	ManagedRoles   []string
	RequestID      string
	RequestedAt    time.Time
}

type ChangeResult struct {
	User        User
	OperationID string
	Replayed    bool
	Changed     bool
}

// ChangeExecutor is deliberately not implemented by the production ZITADEL
// adapter yet. A future implementation must use a fixed project, preserve
// unrelated roles, and own a durable, idempotent command journal.
type ChangeExecutor interface {
	ApplyRoleChange(context.Context, RoleChange) (ChangeResult, error)
}

type AuditEvent struct {
	Action       string    `json:"action"`
	ActorSubject string    `json:"actorSubject"`
	TargetUserID string    `json:"targetUserId,omitempty"`
	BeforeRoles  []string  `json:"beforeRoles,omitempty"`
	AfterRoles   []string  `json:"afterRoles,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	RequestID    string    `json:"requestId,omitempty"`
	OccurredAt   time.Time `json:"occurredAt"`
}

type AuditSink interface {
	Record(context.Context, AuditEvent) error
}

type sessionResolver interface {
	ResolveSession(*http.Request) (session.Session, string, error)
}

type Service struct {
	resolver   sessionResolver
	directory  Directory
	executor   ChangeExecutor
	audit      AuditSink
	origins    map[string]struct{}
	logger     *slog.Logger
	now        func() time.Time
	limits     *rateLimits
	manageable map[string]struct{}
}

func NewService(resolver sessionResolver, directory Directory, executor ChangeExecutor, audit AuditSink, allowedOrigins []string, logger *slog.Logger) *Service {
	return newService(resolver, directory, executor, audit, allowedOrigins, ManageableRoles, logger)
}

func NewProductService(resolver sessionResolver, directory Directory, executor ChangeExecutor, audit AuditSink, allowedOrigins []string, logger *slog.Logger) *Service {
	return newService(resolver, directory, executor, audit, allowedOrigins, ProductManageableRoles, logger)
}

func newService(resolver sessionResolver, directory Directory, executor ChangeExecutor, audit AuditSink, allowedOrigins, manageableRoles []string, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	origins := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		if origin = strings.TrimRight(strings.TrimSpace(origin), "/"); origin != "" {
			origins[origin] = struct{}{}
		}
	}
	manageable := make(map[string]struct{}, len(manageableRoles))
	for _, role := range manageableRoles {
		manageable[role] = struct{}{}
	}
	return &Service{
		resolver: resolver, directory: directory, executor: executor, audit: audit, origins: origins, logger: logger,
		now: time.Now, limits: newRateLimits(30, 10, time.Minute), manageable: manageable,
	}
}

func (s *Service) PortalAccessHandler(response http.ResponseWriter, request *http.Request) {
	if s.resolver == nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "portal_access_unavailable"})
		return
	}
	current, _, err := s.resolver.ResolveSession(request)
	if err != nil {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	roles, _ := s.normalizeDirectoryRoles(current.PlatformRoles)
	product := func(id string, prefixes []string, always bool) map[string]any {
		assigned := make([]string, 0, len(roles))
		for _, role := range roles {
			for _, prefix := range prefixes {
				if strings.HasPrefix(role, prefix) {
					assigned = append(assigned, role)
					break
				}
			}
		}
		status := "unassigned"
		if always || len(assigned) > 0 {
			status = "active"
		}
		return map[string]any{"id": id, "status": status, "roles": assigned, "source": "iam"}
	}
	revisionHash := sha256.Sum256([]byte(current.Subject + "\x00" + strings.Join(roles, "\x00") + "\x00" + current.PlatformRolesRefreshedAt.UTC().Format(time.RFC3339Nano)))
	writeJSON(response, http.StatusOK, map[string]any{
		"revision": fmt.Sprintf("r%x", revisionHash[:8]),
		"products": []map[string]any{
			product("huiguang", []string{"huiguang:"}, false),
			product("yingguang", []string{"yingguang:"}, false),
			product("lingguang", []string{"lingguang:"}, false),
			product("points", []string{"platform:points-"}, true),
		},
	})
}

func (s *Service) SearchHandler(response http.ResponseWriter, request *http.Request) {
	actor, ok := s.authorize(response, request, "IAM_POINTS_ROLE_SEARCH_DENIED", "")
	if !ok {
		return
	}
	if !s.limits.allow(actor.Subject, false, s.now()) {
		s.denied(request, actor.Subject, "", "IAM_POINTS_ROLE_SEARCH_DENIED", "rate_limited")
		writeJSON(response, http.StatusTooManyRequests, map[string]string{"error": "iam_role_rate_limited"})
		return
	}
	var input struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeJSON(response, requestErrorStatus(err), map[string]string{"error": "invalid_request"})
		return
	}
	input.Query = strings.TrimSpace(input.Query)
	if runes := utf8.RuneCountInString(input.Query); runes < 3 || runes > 64 || input.Limit < 1 || input.Limit > 10 {
		writeJSON(response, http.StatusUnprocessableEntity, map[string]string{"error": "invalid_request"})
		return
	}
	if s.directory == nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "iam_role_directory_unavailable"})
		return
	}
	users, err := s.directory.SearchUsers(request.Context(), input.Query, input.Limit)
	if err != nil {
		s.upstreamError(response, err)
		return
	}
	result := make([]User, 0, len(users))
	for _, user := range users {
		if normalized, valid := s.normalizeUser(user); valid {
			result = append(result, normalized)
		}
	}
	response.Header().Set("Cache-Control", "no-store")
	writeJSON(response, http.StatusOK, map[string]any{"users": result})
}

func (s *Service) ResolveHandler(response http.ResponseWriter, request *http.Request) {
	actor, ok := s.authorize(response, request, "IAM_POINTS_ROLE_RESOLVE_DENIED", "")
	if !ok {
		return
	}
	if !s.limits.allow(actor.Subject, false, s.now()) {
		writeJSON(response, http.StatusTooManyRequests, map[string]string{"error": "iam_role_rate_limited"})
		return
	}
	var input struct {
		UserID string `json:"userId"`
	}
	if err := decodeJSON(response, request, &input); err != nil || !validUserID(input.UserID) {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	user, err := s.getUser(request.Context(), input.UserID)
	if err != nil {
		s.upstreamError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"user": user})
}

func (s *Service) UpdateHandler(response http.ResponseWriter, request *http.Request) {
	targetID := chi.URLParam(request, "userID")
	actor, ok := s.authorize(response, request, "IAM_POINTS_ROLES_UPDATE_DENIED", targetID)
	if !ok {
		return
	}
	if !validUserID(targetID) {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if targetID == actor.Subject {
		s.denied(request, actor.Subject, targetID, "IAM_POINTS_ROLES_UPDATE_DENIED", "self_modification_forbidden")
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "iam_self_role_change_forbidden"})
		return
	}
	if !s.limits.allow(actor.Subject, true, s.now()) {
		s.denied(request, actor.Subject, targetID, "IAM_POINTS_ROLES_UPDATE_DENIED", "rate_limited")
		writeJSON(response, http.StatusTooManyRequests, map[string]string{"error": "iam_role_rate_limited"})
		return
	}
	var input struct {
		Roles []string `json:"roles"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeJSON(response, requestErrorStatus(err), map[string]string{"error": "invalid_request"})
		return
	}
	desired, valid := s.normalizeRequestedRoles(input.Roles)
	if !valid {
		s.denied(request, actor.Subject, targetID, "IAM_POINTS_ROLES_UPDATE_DENIED", "role_not_allowlisted")
		writeJSON(response, http.StatusUnprocessableEntity, map[string]string{"error": "iam_role_not_manageable"})
		return
	}
	current, err := s.getUser(request.Context(), targetID)
	if err != nil {
		s.upstreamError(response, err)
		return
	}
	before, _ := s.normalizeDirectoryRoles(current.Roles)
	if slices.Equal(before, desired) && s.executor == nil {
		current.Roles = desired
		writeJSON(response, http.StatusOK, map[string]any{"user": current, "changed": false})
		return
	}
	idempotencyKey := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if !validIdempotencyKey(idempotencyKey) {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "idempotency_key_required"})
		return
	}
	if s.executor == nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "iam_role_change_unavailable"})
		return
	}
	change := RoleChange{
		IdempotencyKey: idempotencyKey,
		ActorSubject:   actor.Subject,
		TargetUserID:   targetID,
		BeforeRoles:    before,
		AfterRoles:     desired,
		ManagedRoles:   s.manageableRoleList(),
		RequestID:      middleware.GetReqID(request.Context()),
		RequestedAt:    s.now().UTC(),
	}
	result, err := s.executor.ApplyRoleChange(request.Context(), change)
	if err != nil {
		if errors.Is(err, ErrIdempotencyConflict) {
			writeJSON(response, http.StatusConflict, map[string]string{"error": "idempotency_conflict"})
			return
		}
		if errors.Is(err, ErrChangeInProgress) {
			writeJSON(response, http.StatusConflict, map[string]string{"error": "request_in_progress"})
			return
		}
		if errors.Is(err, ErrReconcileRequired) {
			writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "iam_role_reconcile_required"})
			return
		}
		s.logger.Warn("apply IAM role change", "error", err, "request_id", change.RequestID, "target_user_id", targetID)
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "iam_role_change_unavailable"})
		return
	}
	updated := current
	updated.Roles = append([]string(nil), result.User.Roles...)
	updated, valid = s.normalizeUser(updated)
	if !valid {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "iam_role_change_unavailable"})
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"user": updated, "changed": result.Changed, "operationId": result.OperationID, "replayed": result.Replayed})
}

func (s *Service) manageableRoleList() []string {
	roles := make([]string, 0, len(s.manageable))
	for role := range s.manageable {
		roles = append(roles, role)
	}
	slices.Sort(roles)
	return roles
}

func (s *Service) authorize(response http.ResponseWriter, request *http.Request, action, target string) (session.Session, bool) {
	if !s.validOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return session.Session{}, false
	}
	if s.resolver == nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "iam_role_management_unavailable"})
		return session.Session{}, false
	}
	current, _, err := s.resolver.ResolveSession(request)
	if err != nil {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return session.Session{}, false
	}
	if !slices.Contains(current.PlatformRoles, IAMManagerRole) {
		s.denied(request, current.Subject, target, action, "iam_manager_required")
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "iam_admin_forbidden"})
		return session.Session{}, false
	}
	return current, true
}

func (s *Service) validOrigin(request *http.Request) bool {
	origin := strings.TrimRight(strings.TrimSpace(request.Header.Get("Origin")), "/")
	_, ok := s.origins[origin]
	return origin != "" && ok
}

func (s *Service) getUser(ctx context.Context, userID string) (User, error) {
	if s.directory == nil {
		return User{}, ErrUnavailable
	}
	user, err := s.directory.GetUser(ctx, userID)
	if err != nil {
		return User{}, err
	}
	user, valid := s.normalizeUser(user)
	if !valid {
		return User{}, ErrUnavailable
	}
	return user, nil
}

func (s *Service) denied(request *http.Request, actor, target, action, reason string) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(request.Context(), AuditEvent{Action: action, ActorSubject: actor, TargetUserID: target, Reason: reason, RequestID: middleware.GetReqID(request.Context()), OccurredAt: s.now().UTC()})
}

func (s *Service) upstreamError(response http.ResponseWriter, err error) {
	if errors.Is(err, ErrUnavailable) {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "iam_role_directory_unavailable"})
		return
	}
	s.logger.Warn("IAM role directory request failed", "error", err)
	writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "iam_role_directory_unavailable"})
}

func (s *Service) normalizeUser(user User) (User, bool) {
	user.ID = strings.TrimSpace(user.ID)
	user.LoginName = strings.TrimSpace(user.LoginName)
	user.DisplayName = strings.TrimSpace(user.DisplayName)
	if user.ID == "" || user.LoginName == "" || user.State != "ACTIVE" {
		return User{}, false
	}
	roles, valid := s.normalizeDirectoryRoles(user.Roles)
	if !valid {
		return User{}, false
	}
	user.Roles = roles
	return user, true
}

func (s *Service) normalizeRequestedRoles(roles []string) ([]string, bool) {
	result := make([]string, 0, len(roles))
	seen := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		role = strings.TrimSpace(role)
		if _, allowed := s.manageable[role]; !allowed {
			return nil, false
		}
		if _, exists := seen[role]; !exists {
			seen[role] = struct{}{}
			result = append(result, role)
		}
	}
	slices.Sort(result)
	return result, true
}

func (s *Service) normalizeDirectoryRoles(roles []string) ([]string, bool) {
	result := make([]string, 0, len(roles))
	seen := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		role = strings.TrimSpace(role)
		if _, allowed := s.manageable[role]; !allowed {
			continue
		}
		if _, exists := seen[role]; !exists {
			seen[role] = struct{}{}
			result = append(result, role)
		}
	}
	slices.Sort(result)
	return result, true
}

func validUserID(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, "/\\\x00")
}

func validIdempotencyKey(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("._:-", char) {
			continue
		}
		return false
	}
	return true
}

func decodeJSON(response http.ResponseWriter, request *http.Request, target any) error {
	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func requestErrorStatus(err error) int {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

type rateLimits struct {
	mu          sync.Mutex
	window      time.Duration
	searchLimit int
	writeLimit  int
	entries     map[string]rateEntry
}

type rateEntry struct {
	start         time.Time
	search, write int
}

func newRateLimits(searchLimit, writeLimit int, window time.Duration) *rateLimits {
	return &rateLimits{window: window, searchLimit: searchLimit, writeLimit: writeLimit, entries: make(map[string]rateEntry)}
}

func (l *rateLimits) allow(actor string, write bool, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.entries[actor]
	if entry.start.IsZero() || now.Sub(entry.start) >= l.window {
		entry = rateEntry{start: now}
	}
	if write {
		if entry.write >= l.writeLimit {
			return false
		}
		entry.write++
	} else {
		if entry.search >= l.searchLimit {
			return false
		}
		entry.search++
	}
	l.entries[actor] = entry
	return true
}
