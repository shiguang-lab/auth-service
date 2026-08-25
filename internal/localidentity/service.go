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
	{ID: "local-ordinary", LoginName: "ordinary@local.test", DisplayName: "普通用户", Roles: []string{platformroleadmin.HuiguangUserRole, platformroleadmin.YingguangUserRole, platformroleadmin.LingguangUserRole}},
	{ID: "local-owner", LoginName: "owner@local.test", DisplayName: "应用所有者", Roles: []string{platformroleadmin.LingguangDevRole}},
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
		"iamCapabilities": map[string]any{
			"pointsRoleAssignments": map[string]any{
				"read": manage, "write": manage,
				"manageableRoles": append([]string(nil), platformroleadmin.ManageableRoles...),
			},
			"productRoleAssignments": map[string]any{
				"read": manage, "write": manage,
				"manageableRoles": append([]string(nil), platformroleadmin.ProductManageableRoles...),
			},
		},
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
	return s.setScopedRoles(ctx, userID, roles, platformroleadmin.ManageableRoles)
}

func (s *Service) SetProductRoles(ctx context.Context, userID string, roles []string) (platformroleadmin.User, error) {
	return s.setScopedRoles(ctx, userID, roles, platformroleadmin.ProductManageableRoles)
}

func (s *Service) SetManagedRoles(ctx context.Context, userID string, roles, managedRoles []string) (platformroleadmin.User, error) {
	return s.setScopedRoles(ctx, userID, roles, managedRoles)
}

func (s *Service) setScopedRoles(ctx context.Context, userID string, desired, scope []string) (platformroleadmin.User, error) {
	if _, ok := findUser(userID); !ok {
		return platformroleadmin.User{}, &platformroleadmin.ProviderError{Code: "user_not_found", Definitive: true}
	}
	current, err := s.roles(ctx, userID)
	if err != nil {
		return platformroleadmin.User{}, err
	}
	next := replaceScopedRoles(current, desired, scope)
	body, err := json.Marshal(next)
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

func replaceScopedRoles(current, desired, scope []string) []string {
	managed := make(map[string]struct{}, len(scope))
	for _, role := range scope {
		managed[role] = struct{}{}
	}
	next := make([]string, 0, len(current)+len(desired))
	for _, role := range current {
		if _, replace := managed[role]; !replace {
			next = append(next, role)
		}
	}
	next = append(next, desired...)
	slices.Sort(next)
	return slices.Compact(next)
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

func fixtureRoleDescription(user fixtureUser) string {
	switch {
	case slices.Contains(user.Roles, platformroleadmin.IAMManagerRole):
		return "积分平台角色授予与撤销，仅限 IAM 管理员"
	case slices.Contains(user.Roles, platformroleadmin.PointsAdminRole):
		return "平台账户、应用、成员、账本与人工调整"
	case slices.Contains(user.Roles, platformroleadmin.PointsAuditorRole):
		return "全局账户、账本与审计只读"
	case user.ID == "local-owner" || user.ID == "local-other-owner":
		return "所属应用、凭据与应用账本，仅限已授权应用"
	default:
		return "个人积分、每日签到与个人账本"
	}
}

var loginPage = template.Must(template.New("local-login").Funcs(template.FuncMap{
	"roleDescription": fixtureRoleDescription,
}).Parse(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>拾光统一登录 · 积分系统</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #030a0d;
      --bg-raised: #061115;
      --surface: #0b151b;
      --surface-strong: #101d24;
      --input: #081217;
      --line: #193036;
      --line-soft: #14272c;
      --text: #edf7f4;
      --body: #b8c6c8;
      --muted: #829499;
      --violet: #9b6cff;
      --violet-soft: #c7b4ff;
      --cyan: #55c8d8;
      --green: #49d27a;
      --green-strong: #25a95a;
      --gold: #d7ae46;
      --danger: #ff6673;
      --radius: 8px;
      font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "PingFang SC", "Microsoft YaHei", sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    * { box-sizing: border-box; }
    html, body { min-height: 100%; margin: 0; }
    body {
      min-width: 320px;
      background: var(--bg);
      color: var(--text);
      font-size: 15px;
      line-height: 1.55;
    }
    button, select { font: inherit; }
    .page-shell { min-height: 100vh; display: flex; flex-direction: column; }
    .brandbar {
      width: min(1180px, calc(100% - 48px));
      margin: 0 auto;
      min-height: 72px;
      display: flex;
      align-items: center;
      gap: 12px;
      border-bottom: 1px solid var(--line-soft);
      color: var(--body);
    }
    .brand-mark {
      width: 30px;
      height: 30px;
      display: inline-grid;
      place-items: center;
      border: 1px solid var(--violet);
      border-radius: 6px;
      color: var(--violet-soft);
      font-size: 14px;
      font-weight: 750;
      letter-spacing: 0;
    }
    .brand-name { color: var(--text); font-weight: 700; letter-spacing: 0; }
    .brand-divider { color: var(--line); }
    .brand-product { color: var(--body); }
    .env-badge {
      margin-left: auto;
      padding: 4px 9px;
      border: 1px solid #2b5a63;
      border-radius: 5px;
      color: var(--cyan);
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0;
      white-space: nowrap;
    }
    .login-layout {
      width: min(980px, calc(100% - 48px));
      margin: auto;
      padding: 64px 0 72px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(360px, 460px);
      align-items: center;
      gap: 72px;
    }
    .intro { max-width: 400px; }
    .eyebrow {
      margin: 0 0 16px;
      color: var(--green);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0;
      text-transform: uppercase;
    }
    h1 { margin: 0; font-size: 42px; line-height: 1.18; letter-spacing: 0; }
    .intro-copy { margin: 18px 0 0; color: var(--body); font-size: 16px; }
    .scope-list { margin: 28px 0 0; padding: 0; list-style: none; display: grid; gap: 12px; }
    .scope-list li { display: flex; align-items: baseline; gap: 10px; color: var(--muted); }
    .scope-list strong { color: var(--text); font-weight: 600; }
    .scope-list span { color: var(--cyan); }
    .panel {
      padding: 28px;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--surface);
      box-shadow: 0 18px 44px rgba(0, 0, 0, .22);
    }
    .panel-kicker { color: var(--violet-soft); font-size: 12px; font-weight: 700; letter-spacing: 0; text-transform: uppercase; }
    .panel h2 { margin: 8px 0 6px; font-size: 24px; line-height: 1.25; }
    .panel-lede { margin: 0 0 24px; color: var(--muted); }
    form { display: grid; gap: 16px; }
    label { color: var(--body); font-size: 13px; font-weight: 600; }
    select {
      display: block;
      width: 100%;
      min-height: 46px;
      margin-top: 7px;
      padding: 0 12px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--input);
      color: var(--text);
      cursor: pointer;
    }
    select:hover { border-color: #2b5961; }
    select:focus-visible, button:focus-visible { outline: 2px solid var(--cyan); outline-offset: 3px; }
    .identity-detail, .return-target {
      padding: 13px 14px;
      border: 1px solid var(--line-soft);
      border-radius: 6px;
      background: var(--bg-raised);
    }
    .detail-label, .return-label { display: block; color: var(--muted); font-size: 11px; letter-spacing: 0; text-transform: uppercase; }
    .identity-detail p { margin: 4px 0 0; color: var(--body); }
    .return-target code {
      display: block;
      margin-top: 4px;
      overflow-wrap: anywhere;
      color: var(--gold);
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
    }
    button {
      min-height: 46px;
      border: 1px solid var(--green-strong);
      border-radius: 6px;
      background: var(--green-strong);
      color: #04110a;
      font-weight: 750;
      cursor: pointer;
      transition: background-color .15s ease, border-color .15s ease;
    }
    button:hover:not(:disabled) { border-color: var(--green); background: var(--green); }
    button:disabled { cursor: wait; opacity: .7; }
    .status { min-height: 24px; margin: -4px 0 0; color: var(--muted); font-size: 13px; }
    .status--busy { color: var(--cyan); }
    .status--error { color: var(--danger); }
    .security-note { margin: 20px 0 0; padding-top: 16px; border-top: 1px solid var(--line-soft); color: var(--muted); font-size: 12px; }
    .footer { width: min(1180px, calc(100% - 48px)); margin: 0 auto; padding: 0 0 22px; color: var(--muted); font-size: 12px; }
    @media (max-width: 760px) {
      .brandbar, .footer, .login-layout { width: min(100% - 32px, 560px); }
      .login-layout { grid-template-columns: 1fr; gap: 28px; padding: 36px 0 44px; }
      .intro { max-width: none; }
      h1 { font-size: 36px; }
      .intro-copy { margin-top: 12px; }
      .scope-list { display: none; }
      .panel { padding: 22px 18px; }
    }
    @media (max-width: 420px) {
      .brandbar { min-height: 62px; }
      .brand-divider, .brand-product { display: none; }
      .env-badge { margin-left: auto; }
      .login-layout { width: calc(100% - 24px); padding-top: 30px; }
      h1 { font-size: 30px; }
      .panel h2 { font-size: 22px; }
      .footer { width: calc(100% - 24px); }
    }
  </style>
</head>
<body>
  <div class="page-shell">
    <header class="brandbar" aria-label="拾光积分系统">
      <span class="brand-mark" aria-hidden="true">S</span>
      <span class="brand-name">拾光本地统一登录</span>
      <span class="brand-divider" aria-hidden="true">/</span>
      <span class="brand-product">积分系统</span>
      <span class="env-badge">LOCAL · 无密钥验收</span>
    </header>
    <main class="login-layout">
      <section class="intro" aria-labelledby="intro-title">
        <p class="eyebrow">Shiguang points</p>
        <h1 id="intro-title">进入积分工作台</h1>
        <p class="intro-copy">使用拾光统一身份进入本地积分系统，验证个人积分、应用权限与平台管理流程。</p>
        <ul class="scope-list" aria-label="本地验收范围">
          <li><span aria-hidden="true">01</span><strong>统一会话</strong> <span>登录、回跳与退出</span></li>
          <li><span aria-hidden="true">02</span><strong>权限边界</strong> <span>个人、应用与平台角色</span></li>
          <li><span aria-hidden="true">03</span><strong>积分中台</strong> <span>账本、凭据与审计</span></li>
        </ul>
      </section>
      <section class="panel" aria-labelledby="login-title">
        <div class="panel-kicker">统一身份认证</div>
        <h2 id="login-title">选择验收身份</h2>
        <p class="panel-lede">这是本地无密钥夹具，仅提供预置身份，不接受任意用户输入。</p>
        <form id="login" novalidate>
          <input type="hidden" name="returnTo" value="{{.ReturnTo}}">
          <label for="userId">登录身份
            <select id="userId" name="userId" autocomplete="off" required>
              {{range .Users}}<option value="{{.ID}}" data-description="{{roleDescription .}}">{{.DisplayName}} · {{.LoginName}}</option>{{end}}
            </select>
          </label>
          <div class="identity-detail">
            <span class="detail-label">该身份可验证</span>
            <p id="roleDescription" aria-live="polite">{{roleDescription (index .Users 0)}}</p>
          </div>
          <div class="return-target">
            <span class="return-label">登录后返回</span>
            <code>{{.ReturnTo}}</code>
          </div>
          <button id="submitLogin" type="submit"><span id="buttonLabel">登录并返回积分系统</span></button>
          <p id="status" class="status" role="status" aria-live="polite"></p>
        </form>
        <p class="security-note">登录状态仅用于本机验收，会话通过同源安全 Cookie 保存。</p>
      </section>
    </main>
    <footer class="footer">拾光积分系统 · 本地开发夹具 · 不连接生产身份服务</footer>
  </div>
  <script>
    (() => {
      const form = document.getElementById('login');
      const select = document.getElementById('userId');
      const description = document.getElementById('roleDescription');
      const status = document.getElementById('status');
      const button = document.getElementById('submitLogin');
      const buttonLabel = document.getElementById('buttonLabel');
      const idleLabel = buttonLabel.textContent;
      select.addEventListener('change', () => {
        description.textContent = select.selectedOptions[0]?.dataset.description || '';
      });
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        if (button.disabled) return;
        button.disabled = true;
        buttonLabel.textContent = '正在建立本地会话…';
        status.className = 'status status--busy';
        status.textContent = '正在验证身份，请稍候。';
        const formData = new FormData(form);
        try {
          const response = await fetch('/api/auth/local/login', {
            method: 'POST', credentials: 'include',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({userId: formData.get('userId'), returnTo: formData.get('returnTo')})
          });
          const body = await response.json().catch(() => ({}));
          if (!response.ok) throw new Error(body.error || 'login_failed');
          if (typeof body.redirect !== 'string') throw new Error('invalid_redirect');
          status.textContent = '登录成功，正在返回积分系统。';
          window.location.assign(body.redirect);
        } catch (error) {
          status.className = 'status status--error';
          status.textContent = error instanceof Error ? error.message : 'login_failed';
          button.disabled = false;
          buttonLabel.textContent = idleLabel;
        }
      });
    })();
  </script>
</body>
</html>`))
