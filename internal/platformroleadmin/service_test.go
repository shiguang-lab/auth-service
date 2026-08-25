package platformroleadmin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/shiguanglab/auth-service/internal/session"
)

const testRoleAdminOrigin = "https://point.shiguanglab.com"

type fakeResolver struct{ current session.Session }

func (f fakeResolver) ResolveSession(*http.Request) (session.Session, string, error) {
	if f.current.Subject == "" {
		return session.Session{}, "", session.ErrNotFound
	}
	return f.current, "fixture-session", nil
}

type memoryDirectory struct {
	mu        sync.Mutex
	users     map[string]User
	writes    int
	err       error
	changeErr error
	changes   []RoleChange
	applied   map[string]ChangeResult
}

func (d *memoryDirectory) SearchUsers(_ context.Context, query string, limit int) ([]User, error) {
	if d.err != nil {
		return nil, d.err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	result := make([]User, 0, limit)
	for _, user := range d.users {
		if strings.Contains(strings.ToLower(user.LoginName+" "+user.DisplayName), strings.ToLower(query)) {
			result = append(result, user)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

func (d *memoryDirectory) GetUser(_ context.Context, userID string) (User, error) {
	if d.err != nil {
		return User{}, d.err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	user, ok := d.users[userID]
	if !ok {
		return User{}, ErrUnavailable
	}
	return user, nil
}

func (d *memoryDirectory) ApplyRoleChange(_ context.Context, change RoleChange) (ChangeResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.changeErr != nil {
		return ChangeResult{}, d.changeErr
	}
	if d.applied == nil {
		d.applied = make(map[string]ChangeResult)
	}
	operationKey := change.ActorSubject + ":" + change.IdempotencyKey
	if result, ok := d.applied[operationKey]; ok {
		result.Replayed = true
		return result, nil
	}
	user, ok := d.users[change.TargetUserID]
	if !ok {
		return ChangeResult{}, ErrUnavailable
	}
	d.changes = append(d.changes, change)
	user.Roles = append([]string(nil), change.AfterRoles...)
	d.users[change.TargetUserID] = user
	d.writes++
	result := ChangeResult{User: user, OperationID: "fixture-operation", Changed: !slices.Equal(change.BeforeRoles, change.AfterRoles)}
	d.applied[operationKey] = result
	return result, nil
}

type memoryAudit struct {
	mu     sync.Mutex
	events []AuditEvent
	err    error
}

func (a *memoryAudit) Record(_ context.Context, event AuditEvent) error {
	if a.err != nil {
		return a.err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	return nil
}

func TestRoleManagementAuthorizationAllowlistAndIdempotency(t *testing.T) {
	directory := testDirectory()
	audit := &memoryAudit{}
	manager := newHandler(NewService(fakeResolver{session.Session{Subject: "iam-manager", PlatformRoles: []string{IAMManagerRole}}}, directory, directory, audit, []string{testRoleAdminOrigin}, nil))

	search := serve(manager, http.MethodPost, "/api/auth/iam/points-role-assignments/search", `{"query":"alice","limit":10}`)
	assertStatus(t, search, http.StatusOK)
	if search.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("search response is cacheable")
	}
	var searchResult struct {
		Users []User `json:"users"`
	}
	if err := json.Unmarshal(search.Body.Bytes(), &searchResult); err != nil || len(searchResult.Users) != 1 || searchResult.Users[0].ID != "target" {
		t.Fatalf("search result = %s", search.Body.String())
	}

	first := serve(manager, http.MethodPut, "/api/auth/iam/points-role-assignments/target", `{"roles":["platform:points-auditor","platform:points-admin"]}`)
	assertStatus(t, first, http.StatusOK)
	second := serve(manager, http.MethodPut, "/api/auth/iam/points-role-assignments/target", `{"roles":["platform:points-admin","platform:points-auditor"]}`)
	assertStatus(t, second, http.StatusOK)
	if directory.writes != 1 {
		t.Fatalf("writes = %d, want 1", directory.writes)
	}
	var replay struct {
		Changed  bool `json:"changed"`
		Replayed bool `json:"replayed"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &replay); err != nil || !replay.Changed || !replay.Replayed {
		t.Fatalf("replay = %s", second.Body.String())
	}
	if len(directory.changes) != 1 || directory.changes[0].ActorSubject != "iam-manager" || directory.changes[0].TargetUserID != "target" {
		t.Fatalf("changes = %#v", directory.changes)
	}

	unmanaged := serve(manager, http.MethodPut, "/api/auth/iam/points-role-assignments/target", `{"roles":["system-admin"]}`)
	assertError(t, unmanaged, http.StatusUnprocessableEntity, "iam_role_not_manageable")
	unknown := serve(manager, http.MethodPut, "/api/auth/iam/points-role-assignments/target", `{"roles":[],"issuer":"forged"}`)
	assertError(t, unknown, http.StatusBadRequest, "invalid_request")
}

func TestProductRoleManagementAndPortalAccess(t *testing.T) {
	directory := testDirectory()
	resolver := fakeResolver{session.Session{
		Subject:       "iam-manager",
		PlatformRoles: []string{IAMManagerRole, HuiguangUserRole, LingguangDevRole, PointsAdminRole},
	}}
	service := NewProductService(resolver, directory, directory, &memoryAudit{}, []string{testRoleAdminOrigin}, nil)
	handler := newProductHandler(service)

	access := serve(handler, http.MethodGet, "/api/auth/portal/access", "")
	assertStatus(t, access, http.StatusOK)
	var accessBody struct {
		Revision string `json:"revision"`
		Products []struct {
			ID     string   `json:"id"`
			Status string   `json:"status"`
			Roles  []string `json:"roles"`
		} `json:"products"`
	}
	if err := json.Unmarshal(access.Body.Bytes(), &accessBody); err != nil || accessBody.Revision == "" || len(accessBody.Products) != 4 {
		t.Fatalf("portal access = %s", access.Body.String())
	}
	if accessBody.Products[0].ID != "huiguang" || accessBody.Products[0].Status != "active" || accessBody.Products[3].ID != "points" || accessBody.Products[3].Status != "active" {
		t.Fatalf("portal products = %#v", accessBody.Products)
	}

	update := serve(handler, http.MethodPut, "/api/auth/iam/product-role-assignments/target", `{"roles":["huiguang:user","yingguang:ops-admin","lingguang:developer"]}`)
	assertStatus(t, update, http.StatusOK)
	if directory.writes != 1 || len(directory.changes) != 1 || len(directory.changes[0].ManagedRoles) != len(ProductManageableRoles) {
		t.Fatalf("product change = writes:%d changes:%#v", directory.writes, directory.changes)
	}
	unmanaged := serve(handler, http.MethodPut, "/api/auth/iam/product-role-assignments/other", `{"roles":["platform:admin"]}`)
	assertError(t, unmanaged, http.StatusUnprocessableEntity, "iam_role_not_manageable")
}

func TestOnlyIAMManagerCanUseAPIAndCannotModifySelf(t *testing.T) {
	for name, roles := range map[string][]string{
		"ordinary":           nil,
		"points-admin":       {PointsAdminRole},
		"auditor":            {PointsAuditorRole},
		"application-member": nil,
	} {
		t.Run(name, func(t *testing.T) {
			service := NewService(fakeResolver{session.Session{Subject: name, PlatformRoles: roles}}, testDirectory(), testDirectory(), &memoryAudit{}, []string{testRoleAdminOrigin}, nil)
			response := serve(newHandler(service), http.MethodPost, "/api/auth/iam/points-role-assignments/search", `{"query":"alice","limit":10}`)
			assertError(t, response, http.StatusForbidden, "iam_admin_forbidden")
		})
	}
	directory := testDirectory()
	service := NewService(fakeResolver{session.Session{Subject: "iam-manager", PlatformRoles: []string{IAMManagerRole, PointsAdminRole}}}, directory, directory, &memoryAudit{}, []string{testRoleAdminOrigin}, nil)
	response := serve(newHandler(service), http.MethodPut, "/api/auth/iam/points-role-assignments/iam-manager", `{"roles":["platform:points-admin"]}`)
	assertError(t, response, http.StatusForbidden, "iam_self_role_change_forbidden")
}

func TestUnavailableAndInvalidDirectoryFailClosed(t *testing.T) {
	resolver := fakeResolver{session.Session{Subject: "iam-manager", PlatformRoles: []string{IAMManagerRole}}}
	service := NewService(resolver, nil, nil, nil, []string{testRoleAdminOrigin}, nil)
	search := serve(newHandler(service), http.MethodPost, "/api/auth/iam/points-role-assignments/search", `{"query":"alice","limit":10}`)
	assertError(t, search, http.StatusServiceUnavailable, "iam_role_directory_unavailable")

	directory := testDirectory()
	directory.users["disabled"] = User{ID: "disabled", LoginName: "disabled", State: "INACTIVE"}
	resolve := serve(newHandler(NewService(resolver, directory, nil, nil, []string{testRoleAdminOrigin}, nil)), http.MethodPost, "/api/auth/iam/points-role-assignments/resolve", `{"userId":"disabled"}`)
	assertError(t, resolve, http.StatusServiceUnavailable, "iam_role_directory_unavailable")

	update := serve(newHandler(NewService(resolver, directory, nil, nil, []string{testRoleAdminOrigin}, nil)), http.MethodPut, "/api/auth/iam/points-role-assignments/target", `{"roles":["platform:points-admin"]}`)
	assertError(t, update, http.StatusServiceUnavailable, "iam_role_change_unavailable")
}

func TestRoleManagementRejectsMissingAndSiblingOrigins(t *testing.T) {
	directory := testDirectory()
	service := NewService(
		fakeResolver{session.Session{Subject: "iam-manager", PlatformRoles: []string{IAMManagerRole}}},
		directory, directory, &memoryAudit{}, []string{testRoleAdminOrigin}, nil,
	)
	handler := newHandler(service)
	for _, origin := range []string{"", "https://huiguang.shiguanglab.com", "https://point.shiguanglab.com.evil.example"} {
		t.Run(origin, func(t *testing.T) {
			response := serveWithOrigin(handler, http.MethodPut, "/api/auth/iam/points-role-assignments/target", `{"roles":["platform:points-admin"]}`, origin)
			assertError(t, response, http.StatusForbidden, "invalid_origin")
		})
	}
	if directory.writes != 0 {
		t.Fatalf("untrusted origins performed %d writes", directory.writes)
	}
}

func TestCommandJournalFailureDoesNotMutateRoles(t *testing.T) {
	directory := testDirectory()
	directory.changeErr = errors.New("command journal unavailable")
	service := NewService(
		fakeResolver{session.Session{Subject: "iam-manager", PlatformRoles: []string{IAMManagerRole}}},
		directory, directory, &memoryAudit{}, []string{testRoleAdminOrigin}, nil,
	)
	response := serve(newHandler(service), http.MethodPut, "/api/auth/iam/points-role-assignments/target", `{"roles":["platform:points-admin"]}`)
	assertError(t, response, http.StatusServiceUnavailable, "iam_role_change_unavailable")
	if directory.writes != 0 || len(directory.changes) != 0 || len(directory.users["target"].Roles) != 0 {
		t.Fatalf("failed command mutated state: writes=%d changes=%#v user=%#v", directory.writes, directory.changes, directory.users["target"])
	}
}

func TestSearchValidationAndRateLimit(t *testing.T) {
	directory := testDirectory()
	service := NewService(fakeResolver{session.Session{Subject: "iam-manager", PlatformRoles: []string{IAMManagerRole}}}, directory, directory, &memoryAudit{}, []string{testRoleAdminOrigin}, nil)
	service.limits = newRateLimits(1, 1, service.limits.window)
	handler := newHandler(service)
	assertError(t, serve(handler, http.MethodPost, "/api/auth/iam/points-role-assignments/search", `{"query":"al","limit":10}`), http.StatusUnprocessableEntity, "invalid_request")
	// Invalid attempts consume the caller's search budget by design.
	assertError(t, serve(handler, http.MethodPost, "/api/auth/iam/points-role-assignments/search", `{"query":"alice","limit":10}`), http.StatusTooManyRequests, "iam_role_rate_limited")

	service = NewService(fakeResolver{session.Session{Subject: "iam-manager", PlatformRoles: []string{IAMManagerRole}}}, directory, directory, &memoryAudit{}, []string{testRoleAdminOrigin}, nil)
	service.limits = newRateLimits(3, 1, service.limits.window)
	handler = newHandler(service)
	assertStatus(t, serve(handler, http.MethodPost, "/api/auth/iam/points-role-assignments/search", `{"query":"alice","limit":10}`), http.StatusOK)
	assertStatus(t, serve(handler, http.MethodPut, "/api/auth/iam/points-role-assignments/target", `{"roles":["platform:points-admin"]}`), http.StatusOK)
	assertError(t, serve(handler, http.MethodPut, "/api/auth/iam/points-role-assignments/other", `{"roles":["platform:points-auditor"]}`), http.StatusTooManyRequests, "iam_role_rate_limited")
}

func testDirectory() *memoryDirectory {
	return &memoryDirectory{users: map[string]User{
		"target": {ID: "target", LoginName: "alice@shiguang", DisplayName: "Alice", State: "ACTIVE"},
		"other":  {ID: "other", LoginName: "bob@shiguang", DisplayName: "Bob", State: "ACTIVE"},
	}}
}

func newHandler(service *Service) http.Handler {
	router := chi.NewRouter()
	router.Post("/api/auth/iam/points-role-assignments/search", service.SearchHandler)
	router.Post("/api/auth/iam/points-role-assignments/resolve", service.ResolveHandler)
	router.Put("/api/auth/iam/points-role-assignments/{userID}", service.UpdateHandler)
	return router
}

func newProductHandler(service *Service) http.Handler {
	router := chi.NewRouter()
	router.Get("/api/auth/portal/access", service.PortalAccessHandler)
	router.Post("/api/auth/iam/product-role-assignments/search", service.SearchHandler)
	router.Post("/api/auth/iam/product-role-assignments/resolve", service.ResolveHandler)
	router.Put("/api/auth/iam/product-role-assignments/{userID}", service.UpdateHandler)
	return router
}

func serve(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	return serveWithOrigin(handler, method, path, body, testRoleAdminOrigin)
}

func serveWithOrigin(handler http.Handler, method, path, body, origin string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", origin)
	request.Header.Set("Idempotency-Key", "fixture-idempotency-key")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertStatus(t *testing.T, response *httptest.ResponseRecorder, status int) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
}

func assertError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	assertStatus(t, response, status)
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != code {
		t.Fatalf("error = %q body=%s", body["error"], response.Body.String())
	}
}
