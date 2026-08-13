// Package localidentity provides an explicit, development-only identity
// fixture for exercising the real Gateway/Auth/Points contracts without a
// ZITADEL tenant or provider credential.
package localidentity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
	"github.com/shiguanglab/auth-service/internal/platformroleadmin"
	"github.com/shiguanglab/auth-service/internal/session"
)

const maxFixtureRequestBytes = 16 << 10

type Config struct {
	Origin         string
	CookieName     string
	CookieTTL      time.Duration
	IdentityIssuer string
	IdentityToken  string
	RedisPrefix    string
}

type fixtureUser struct {
	ID          string
	LoginName   string
	DisplayName string
	Roles       []string
}

var fixtureUsers = []fixtureUser{
	{ID: "local-ordinary", LoginName: "ordinary@local.test", DisplayName: "普通用户"},
	{ID: "local-owner", LoginName: "owner@local.test", DisplayName: "应用所有者"},
	{ID: "local-other-owner", LoginName: "other-owner@local.test", DisplayName: "其他应用所有者"},
	{ID: "local-auditor", LoginName: "auditor@local.test", DisplayName: "积分审计员", Roles: []string{platformroleadmin.PointsAuditorRole}},
	{ID: "local-points-admin", LoginName: "points-admin@local.test", DisplayName: "积分平台管理员", Roles: []string{platformroleadmin.PointsAdminRole}},
	{ID: "local-iam-admin", LoginName: "iam-admin@local.test", DisplayName: "IAM 管理员", Roles: []string{platformroleadmin.IAMManagerRole}},
}

type Service struct {
	cfg       Config
	sessions  session.Store
	redis     *redis.Client
	executor  *platformroleadmin.DurableChangeExecutor
	logger    *slog.Logger
	tokenHash [32]byte
	auditMu   sync.Mutex
	audit     []platformroleadmin.AuditEvent
}

func New(cfg Config, sessions session.Store, options *redis.Options, logger *slog.Logger) (*Service, error) {
	if sessions == nil || options == nil {
		return nil, errors.New("local identity fixture requires sessions and Redis")
	}
	cfg.Origin = strings.TrimRight(strings.TrimSpace(cfg.Origin), "/")
	cfg.RedisPrefix = strings.TrimSpace(cfg.RedisPrefix)
	if cfg.RedisPrefix == "" {
		cfg.RedisPrefix = "auth:local-identity:"
	}
	if cfg.Origin == "" || cfg.CookieName == "" || cfg.CookieTTL <= 0 || cfg.IdentityIssuer == "" || len(cfg.IdentityToken) < 16 {
		return nil, errors.New("local identity fixture configuration is incomplete")
	}
	if logger == nil {
		logger = slog.Default()
	}
	service := &Service{
		cfg: cfg, sessions: sessions, redis: redis.NewClient(options),
		logger: logger, tokenHash: sha256.Sum256([]byte(cfg.IdentityToken)),
	}
	return service, nil
}

func (s *Service) SetExecutor(executor *platformroleadmin.DurableChangeExecutor) {
	s.executor = executor
}

func (s *Service) Close() error { return s.redis.Close() }

func (s *Service) Ping(ctx context.Context) error { return s.redis.Ping(ctx).Err() }

func (s *Service) Seed(ctx context.Context) error {
	for _, user := range fixtureUsers {
		roles, err := json.Marshal(user.Roles)
		if err != nil {
			return err
		}
		if err := s.redis.SetNX(ctx, s.roleKey(user.ID), roles, 0).Err(); err != nil {
			return fmt.Errorf("seed local identity roles: %w", err)
		}
	}
	return nil
}

func (s *Service) LoginPage(response http.ResponseWriter, request *http.Request) {
	returnTo := s.safeReturnTo(request.URL.Query().Get("return_to"))
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	_ = loginPage.Execute(response, map[string]any{"ReturnTo": returnTo, "Users": fixtureUsers})
}

func (s *Service) Login(response http.ResponseWriter, request *http.Request) {
	if !s.validOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	var input struct {
		UserID   string `json:"userId"`
		ReturnTo string `json:"returnTo"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	user, ok := findUser(input.UserID)
	if !ok {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	roles, err := s.roles(request.Context(), user.ID)
	if err != nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "fixture_unavailable"})
		return
	}
	sessionID, err := randomValue(32)
	if err != nil {
		writeJSON(response, http.StatusInternalServerError, map[string]string{"error": "fixture_unavailable"})
		return
	}
	now := time.Now().UTC()
	value := session.Session{
		AssertionSessionID: sessionID, Subject: user.ID, DisplayName: user.DisplayName,
		PreferredUsername: user.LoginName, Entitlements: []string{"platform:access"},
		PlatformRoles: roles, PlatformRolesRefreshedAt: now, AuthenticationTime: now,
		AuthenticationMethods: []string{"local_fixture"}, CreatedAt: now, LastSeenAt: now,
	}
	if err := s.sessions.Put(request.Context(), sessionID, value); err != nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "fixture_unavailable"})
		return
	}
	s.setCookie(response, sessionID, int(s.cfg.CookieTTL.Seconds()))
	writeJSON(response, http.StatusOK, map[string]string{"redirect": s.safeReturnTo(input.ReturnTo)})
}

func (s *Service) Session(response http.ResponseWriter, request *http.Request) {
	value, _, err := s.ResolveSession(request)
	if err != nil {
		writeJSON(response, http.StatusUnauthorized, map[string]any{"authenticated": false})
		return
	}
	manage := slices.Contains(value.PlatformRoles, platformroleadmin.IAMManagerRole)
	writeJSON(response, http.StatusOK, map[string]any{
		"authenticated": true, "subject": value.Subject, "displayName": value.DisplayName,
		"preferredUsername": value.PreferredUsername, "entitlements": value.Entitlements,
		"roles": value.Roles, "platformRoles": value.PlatformRoles,
		"iamCapabilities": map[string]any{"pointsRoleAssignments": map[string]any{
			"read": manage, "write": manage,
			"manageableRoles": []string{platformroleadmin.PointsAdminRole, platformroleadmin.PointsAuditorRole},
		}},
	})
}

func (s *Service) Logout(response http.ResponseWriter, request *http.Request) {
	if !s.validOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return
	}
	_, sessionID, err := s.ResolveSession(request)
	if err == nil {
		_ = s.sessions.Revoke(request.Context(), sessionID, time.Now().UTC())
	}
	s.setCookie(response, "", -1)
	writeJSON(response, http.StatusOK, map[string]string{"redirect": "/"})
}

func (s *Service) ResolveSession(request *http.Request) (session.Session, string, error) {
	cookie, err := request.Cookie(s.cfg.CookieName)
	if err != nil || cookie.Value == "" {
		return session.Session{}, "", session.ErrNotFound
	}
	value, err := s.sessions.Get(request.Context(), cookie.Value)
	if err != nil || !value.RevokedAt.IsZero() {
		return session.Session{}, "", session.ErrNotFound
	}
	value, err = s.Refresh(request.Context(), cookie.Value, value)
	if err != nil {
		return session.Session{}, "", err
	}
	return value, cookie.Value, nil
}

func (s *Service) Refresh(ctx context.Context, sessionID string, current session.Session) (session.Session, error) {
	roles, err := s.roles(ctx, current.Subject)
	if err != nil {
		return session.Session{}, err
	}
	return s.sessions.UpdatePlatformRoles(ctx, sessionID, current.Subject, roles, time.Now().UTC())
}

func (s *Service) SearchUsers(ctx context.Context, query string, limit int) ([]platformroleadmin.User, error) {
	needle := strings.ToLower(strings.TrimSpace(query))
	result := make([]platformroleadmin.User, 0, limit)
	for _, user := range fixtureUsers {
		if !strings.Contains(strings.ToLower(user.LoginName+" "+user.DisplayName), needle) {
			continue
		}
		value, err := s.GetUser(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
		if len(result) == limit {
			break
		}
	}
	return result, nil
}

func (s *Service) GetUser(ctx context.Context, userID string) (platformroleadmin.User, error) {
	user, ok := findUser(userID)
	if !ok {
		return platformroleadmin.User{}, platformroleadmin.ErrUnavailable
	}
	roles, err := s.roles(ctx, user.ID)
	if err != nil {
		return platformroleadmin.User{}, err
	}
	return platformroleadmin.User{ID: user.ID, LoginName: user.LoginName, DisplayName: user.DisplayName, State: "ACTIVE", Roles: roles}, nil
}

func (s *Service) SetPointsRoles(ctx context.Context, userID string, roles []string) (platformroleadmin.User, error) {
	if _, ok := findUser(userID); !ok {
		return platformroleadmin.User{}, &platformroleadmin.ProviderError{Code: "user_not_found", Definitive: true}
	}
	body, err := json.Marshal(roles)
	if err != nil {
		return platformroleadmin.User{}, err
	}
	if err := s.redis.Set(ctx, s.roleKey(userID), body, 0).Err(); err != nil {
		return platformroleadmin.User{}, err
	}
	if failed, err := s.redis.GetDel(ctx, s.failureKey(userID)).Result(); err == nil && failed == "unknown" {
		return platformroleadmin.User{}, context.DeadlineExceeded
	}
	return s.GetUser(ctx, userID)
}

func (s *Service) Record(_ context.Context, event platformroleadmin.AuditEvent) error {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	s.audit = append(s.audit, event)
	return nil
}

func (s *Service) SearchIdentityUsers(response http.ResponseWriter, request *http.Request) {
	if !s.authorizeIdentityService(request) {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var input struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}
	if err := decodeJSON(response, request, &input); err != nil || input.Limit < 1 || input.Limit > 10 {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	users, err := s.SearchUsers(request.Context(), input.Query, input.Limit)
	if err != nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "fixture_unavailable"})
		return
	}
	result := make([]map[string]any, 0, len(users))
	for _, user := range users {
		result = append(result, identityUserResponse(user))
	}
	writeJSON(response, http.StatusOK, map[string]any{"users": result})
}

func (s *Service) ResolveIdentityUser(response http.ResponseWriter, request *http.Request) {
	if !s.authorizeIdentityService(request) {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var input struct {
		UserID string `json:"userId"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	user, err := s.GetUser(request.Context(), input.UserID)
	if err != nil {
		writeJSON(response, http.StatusNotFound, map[string]string{"error": "user_not_found"})
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"user": identityUserResponse(user)})
}

func (s *Service) FailNextProviderWrite(response http.ResponseWriter, request *http.Request) {
	manager, ok := s.requireManager(response, request)
	if !ok {
		return
	}
	var input struct {
		TargetUserID string `json:"targetUserId"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if _, ok := findUser(input.TargetUserID); !ok {
		writeJSON(response, http.StatusNotFound, map[string]string{"error": "user_not_found"})
		return
	}
	if err := s.redis.Set(request.Context(), s.failureKey(input.TargetUserID), "unknown", 5*time.Minute).Err(); err != nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "fixture_unavailable"})
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "armed", "actor": manager.Subject})
}

func (s *Service) ListCommands(response http.ResponseWriter, request *http.Request) {
	manager, ok := s.requireManager(response, request)
	if !ok {
		return
	}
	if s.executor == nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "fixture_unavailable"})
		return
	}
	commands, err := s.executor.ListRecoverableCommands(request.Context(), platformroleadmin.NewCommandManager(manager.Subject, manager.PlatformRoles), 50)
	if err != nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "fixture_unavailable"})
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"commands": commands})
}

func (s *Service) RetryCommand(response http.ResponseWriter, request *http.Request) {
	manager, ok := s.requireManager(response, request)
	if !ok {
		return
	}
	if s.executor == nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"error": "fixture_unavailable"})
		return
	}
	result, err := s.executor.RetryCommand(request.Context(), platformroleadmin.NewCommandManager(manager.Subject, manager.PlatformRoles), chi.URLParam(request, "operationID"))
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, platformroleadmin.ErrReconcileRequired) {
			status = http.StatusServiceUnavailable
		}
		writeJSON(response, status, map[string]string{"error": "retry_failed"})
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"user":        result.User,
		"operationId": result.OperationID,
		"replayed":    result.Replayed,
		"changed":     result.Changed,
	})
}

func (s *Service) requireManager(response http.ResponseWriter, request *http.Request) (session.Session, bool) {
	if !s.validOrigin(request) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "invalid_origin"})
		return session.Session{}, false
	}
	current, _, err := s.ResolveSession(request)
	if err != nil {
		writeJSON(response, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return session.Session{}, false
	}
	if !slices.Contains(current.PlatformRoles, platformroleadmin.IAMManagerRole) {
		writeJSON(response, http.StatusForbidden, map[string]string{"error": "iam_admin_forbidden"})
		return session.Session{}, false
	}
	return current, true
}

func (s *Service) roles(ctx context.Context, userID string) ([]string, error) {
	body, err := s.redis.Get(ctx, s.roleKey(userID)).Bytes()
	if err != nil {
		return nil, err
	}
	var roles []string
	if err := json.Unmarshal(body, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

func (s *Service) validOrigin(request *http.Request) bool {
	return strings.TrimRight(strings.TrimSpace(request.Header.Get("Origin")), "/") == s.cfg.Origin
}

func (s *Service) authorizeIdentityService(request *http.Request) bool {
	actual := sha256.Sum256([]byte(strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")))
	return subtle.ConstantTimeCompare(actual[:], s.tokenHash[:]) == 1
}

func (s *Service) setCookie(response http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(response, &http.Cookie{Name: s.cfg.CookieName, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func (s *Service) roleKey(userID string) string    { return s.cfg.RedisPrefix + "roles:" + userID }
func (s *Service) failureKey(userID string) string { return s.cfg.RedisPrefix + "fail-next:" + userID }

func identityUserResponse(user platformroleadmin.User) map[string]any {
	return map[string]any{
		"id":          user.ID,
		"loginName":   user.LoginName,
		"displayName": user.DisplayName,
		"state":       "USER_STATE_ACTIVE",
	}
}

func findUser(userID string) (fixtureUser, bool) {
	for _, user := range fixtureUsers {
		if user.ID == strings.TrimSpace(userID) {
			return user, true
		}
	}
	return fixtureUser{}, false
}

func (s *Service) safeReturnTo(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "/"
	}
	if strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") {
		return value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Scheme+"://"+parsed.Host != s.cfg.Origin {
		return "/"
	}
	return parsed.String()
}

func randomValue(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func decodeJSON(response http.ResponseWriter, request *http.Request, target any) error {
	request.Body = http.MaxBytesReader(response, request.Body, maxFixtureRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("one JSON value is required")
	}
	return nil
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

var loginPage = template.Must(template.New("local-login").Parse(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>拾光本地统一登录</title></head><body><main><h1>拾光本地统一登录</h1><p>仅用于无密钥本地契约验收。</p><form id="login"><input type="hidden" name="returnTo" value="{{.ReturnTo}}"><label>身份<select name="userId">{{range .Users}}<option value="{{.ID}}">{{.DisplayName}} ({{.ID}})</option>{{end}}</select></label><button type="submit">登录并返回积分系统</button></form><pre id="status"></pre></main><script>document.getElementById('login').addEventListener('submit',async(e)=>{e.preventDefault();const f=new FormData(e.target);const r=await fetch('/api/auth/local/login',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({userId:f.get('userId'),returnTo:f.get('returnTo')})});const b=await r.json();if(r.ok)location.assign(b.redirect);else document.getElementById('status').textContent=b.error||'login_failed'});</script></body></html>`))
