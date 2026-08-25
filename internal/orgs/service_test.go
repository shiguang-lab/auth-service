package orgs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/shiguanglab/auth-service/internal/config"
	"github.com/shiguanglab/auth-service/internal/session"
	"github.com/shiguanglab/auth-service/internal/zitadel"
)

const (
	testProject = "project-1"
	testOrigin  = "https://shiguanglab.com"
)

type fakeDirectory struct {
	organizations  map[string]string
	authorizations map[string]zitadel.Authorization
	users          map[string]zitadel.User
	roleCreates    int
	grantCreates   int
	nextID         int
	searchErr      error
}

func newFakeDirectory() *fakeDirectory {
	return &fakeDirectory{
		organizations:  map[string]string{},
		authorizations: map[string]zitadel.Authorization{},
		users:          map[string]zitadel.User{},
	}
}

func (f *fakeDirectory) CreateOrganization(_ context.Context, name string) (zitadel.Organization, error) {
	f.nextID++
	id := "org-" + itoa(f.nextID)
	f.organizations[id] = name
	return zitadel.Organization{ID: id, Name: name}, nil
}

func (f *fakeDirectory) SearchOrganizationsByIDs(_ context.Context, ids []string) ([]zitadel.Organization, error) {
	var result []zitadel.Organization
	for _, id := range ids {
		if name, ok := f.organizations[id]; ok {
			result = append(result, zitadel.Organization{ID: id, Name: name})
		}
	}
	return result, nil
}

func (f *fakeDirectory) EnsureProjectRole(context.Context, string, string, string) error {
	f.roleCreates++
	return nil
}

func (f *fakeDirectory) EnsureProjectGrant(context.Context, string, string, []string) error {
	f.grantCreates++
	return nil
}

func (f *fakeDirectory) CreateAuthorization(_ context.Context, userID, _, orgID string, roles []string) (string, error) {
	for _, existing := range f.authorizations {
		if existing.UserID == userID && existing.OrganizationID == orgID {
			return "", &zitadel.APIError{StatusCode: http.StatusConflict}
		}
	}
	f.nextID++
	id := "authz-" + itoa(f.nextID)
	user := f.users[userID]
	f.authorizations[id] = zitadel.Authorization{
		ID: id, UserID: userID, OrganizationID: orgID,
		Roles: append([]string(nil), roles...), State: "STATE_ACTIVE",
		DisplayName: user.DisplayName, LoginName: user.LoginName,
	}
	return id, nil
}

func (f *fakeDirectory) UpdateAuthorization(_ context.Context, id string, roles []string) error {
	value, ok := f.authorizations[id]
	if !ok {
		return &zitadel.APIError{StatusCode: http.StatusNotFound}
	}
	value.Roles = append([]string(nil), roles...)
	f.authorizations[id] = value
	return nil
}

func (f *fakeDirectory) DeleteAuthorization(_ context.Context, id string) error {
	if _, ok := f.authorizations[id]; !ok {
		return &zitadel.APIError{StatusCode: http.StatusNotFound}
	}
	delete(f.authorizations, id)
	return nil
}

func (f *fakeDirectory) ListAuthorizations(_ context.Context, filter zitadel.AuthorizationFilter) ([]zitadel.Authorization, error) {
	var result []zitadel.Authorization
	for _, value := range f.authorizations {
		if filter.UserID != "" && value.UserID != filter.UserID {
			continue
		}
		if filter.OrganizationID != "" && value.OrganizationID != filter.OrganizationID {
			continue
		}
		result = append(result, value)
	}
	return result, nil
}

func (f *fakeDirectory) GetUserByLoginName(_ context.Context, loginName string) (zitadel.User, error) {
	for _, user := range f.users {
		if strings.EqualFold(user.LoginName, loginName) {
			return user, nil
		}
	}
	return zitadel.User{}, &zitadel.APIError{StatusCode: http.StatusNotFound}
}

func (f *fakeDirectory) SearchUsersByIDs(_ context.Context, ids []string) ([]zitadel.User, error) {
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	var result []zitadel.User
	for _, id := range ids {
		if user, ok := f.users[id]; ok {
			result = append(result, user)
		}
	}
	return result, nil
}

func (f *fakeDirectory) SearchUsers(_ context.Context, query string, limit int) ([]zitadel.User, error) {
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	var result []zitadel.User
	query = strings.ToLower(query)
	for _, user := range f.users {
		if !strings.Contains(strings.ToLower(user.LoginName), query) && !strings.Contains(strings.ToLower(user.DisplayName), query) {
			continue
		}
		result = append(result, user)
		if len(result) == limit {
			break
		}
	}
	return result, nil
}

type staticResolver struct {
	store session.Store
}

func (r staticResolver) ResolveSession(request *http.Request) (session.Session, string, error) {
	cookie, err := request.Cookie("__Secure-sg_session")
	if err != nil {
		return session.Session{}, "", session.ErrNotFound
	}
	value, err := r.store.Get(request.Context(), cookie.Value)
	if err != nil {
		return session.Session{}, "", err
	}
	return value, cookie.Value, nil
}

func newTestService(t *testing.T) (*Service, *fakeDirectory, session.Store) {
	t.Helper()
	directory := newFakeDirectory()
	store := session.NewMemoryStore()
	cfg := config.Config{
		PublicOrigin:               testOrigin,
		AllowedReturnOrigins:       []string{"https://opc.shiguanglab.com"},
		ZitadelProjectID:           testProject,
		ZitadelOrganizationID:      "platform-org",
		IdentityAPIToken:           strings.Repeat("i", 40),
		PointsIdentityServiceToken: strings.Repeat("p", 40),
	}
	service := NewService(cfg, store, staticResolver{store}, directory, nil)
	return service, directory, store
}

func seedSession(t *testing.T, store session.Store, subject string) string {
	t.Helper()
	id := "session-" + subject
	err := store.Put(context.Background(), id, session.Session{
		AssertionSessionID: "assert-" + subject,
		Subject:            subject,
		DisplayName:        "User " + subject,
		CreatedAt:          time.Now().UTC(),
		LastSeenAt:         time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return id
}

func routerFor(service *Service) http.Handler {
	router := chi.NewRouter()
	router.Post("/api/auth/context", service.SwitchContextHandler)
	router.Post("/api/account/orgs", service.CreateOrganizationHandler)
	router.Get("/api/account/orgs", service.ListMyOrganizationsHandler)
	router.Get("/api/account/orgs/{orgID}/members", service.ListMembersHandler)
	router.Post("/api/account/orgs/{orgID}/members", service.AddMemberHandler)
	router.Patch("/api/account/orgs/{orgID}/members/{userID}", service.UpdateMemberHandler)
	router.Delete("/api/account/orgs/{orgID}/members/{userID}", service.RemoveMemberHandler)
	router.Group(func(identityAPI chi.Router) {
		identityAPI.Use(service.RequireIdentityAPIToken)
		identityAPI.Post("/v1/identity/users/batch-get", service.BatchGetUsersHandler)
		identityAPI.Get("/v1/identity/orgs/{orgID}/members", service.ServiceListMembersHandler)
	})
	router.Group(func(pointsIdentity chi.Router) {
		pointsIdentity.Use(service.RequirePointsIdentityServiceToken)
		pointsIdentity.Post("/v1/identity/users/search", service.SearchUsersHandler)
		pointsIdentity.Post("/v1/identity/users/resolve", service.ResolveUserHandler)
	})
	return router
}

func doJSON(t *testing.T, handler http.Handler, method, path, sessionID, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", testOrigin)
	if sessionID != "" {
		request.AddCookie(&http.Cookie{Name: "__Secure-sg_session", Value: sessionID})
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestCreateOrganizationGrantsAdminToCreator(t *testing.T) {
	service, directory, store := newTestService(t)
	sessionID := seedSession(t, store, "alice")
	handler := routerFor(service)

	response := doJSON(t, handler, http.MethodPost, "/api/account/orgs", sessionID, `{"name":"深圳拾光"}`, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("create organization: status %d body %s", response.Code, response.Body.String())
	}
	if directory.grantCreates != 1 || directory.roleCreates != 3 {
		t.Fatalf("expected project grant and roles to be ensured, got grants=%d roles=%d", directory.grantCreates, directory.roleCreates)
	}
	var created struct {
		ID    string   `json:"id"`
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(created.Roles) != 1 || created.Roles[0] != RoleAdmin {
		t.Fatalf("creator should be org admin, got %v", created.Roles)
	}

	listed := doJSON(t, handler, http.MethodGet, "/api/account/orgs", sessionID, "", nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), created.ID) {
		t.Fatalf("list organizations: status %d body %s", listed.Code, listed.Body.String())
	}
}

func TestSwitchContextRequiresMembership(t *testing.T) {
	service, directory, store := newTestService(t)
	aliceSession := seedSession(t, store, "alice")
	bobSession := seedSession(t, store, "bob")
	directory.users["bob"] = zitadel.User{ID: "bob", LoginName: "bob@shiguang", DisplayName: "Bob", State: "USER_STATE_ACTIVE"}
	handler := routerFor(service)

	created := doJSON(t, handler, http.MethodPost, "/api/account/orgs", aliceSession, `{"name":"org-a"}`, nil)
	var organization struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(created.Body.Bytes(), &organization)

	denied := doJSON(t, handler, http.MethodPost, "/api/auth/context", bobSession, `{"organizationId":"`+organization.ID+`"}`, nil)
	if denied.Code != http.StatusNotFound {
		t.Fatalf("non-member switch should 404, got %d", denied.Code)
	}

	switched := doJSON(t, handler, http.MethodPost, "/api/auth/context", aliceSession, `{"organizationId":"`+organization.ID+`"}`, nil)
	if switched.Code != http.StatusOK {
		t.Fatalf("member switch failed: %d %s", switched.Code, switched.Body.String())
	}
	stored, _ := store.Get(context.Background(), aliceSession)
	if stored.OrganizationID != organization.ID || !containsRole(stored.Roles, RoleAdmin) {
		t.Fatalf("session not updated: %+v", stored)
	}

	personal := doJSON(t, handler, http.MethodPost, "/api/auth/context", aliceSession, `{"organizationId":""}`, nil)
	if personal.Code != http.StatusOK {
		t.Fatalf("switch back to personal failed: %d", personal.Code)
	}
	stored, _ = store.Get(context.Background(), aliceSession)
	if stored.OrganizationID != "" || stored.Roles != nil {
		t.Fatalf("personal context should clear organization, got %+v", stored)
	}
}

func TestMemberManagementLifecycle(t *testing.T) {
	service, directory, store := newTestService(t)
	aliceSession := seedSession(t, store, "alice")
	directory.users["bob"] = zitadel.User{ID: "bob", LoginName: "bob@shiguang", DisplayName: "Bob", State: "USER_STATE_ACTIVE"}
	handler := routerFor(service)

	created := doJSON(t, handler, http.MethodPost, "/api/account/orgs", aliceSession, `{"name":"org-a"}`, nil)
	var organization struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(created.Body.Bytes(), &organization)
	base := "/api/account/orgs/" + organization.ID + "/members"

	added := doJSON(t, handler, http.MethodPost, base, aliceSession, `{"loginName":"bob@shiguang","role":"org:member"}`, nil)
	if added.Code != http.StatusCreated {
		t.Fatalf("add member: %d %s", added.Code, added.Body.String())
	}
	duplicate := doJSON(t, handler, http.MethodPost, base, aliceSession, `{"loginName":"bob@shiguang","role":"org:member"}`, nil)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate member should conflict, got %d", duplicate.Code)
	}

	promoted := doJSON(t, handler, http.MethodPatch, base+"/bob", aliceSession, `{"role":"org:admin"}`, nil)
	if promoted.Code != http.StatusOK {
		t.Fatalf("promote member: %d", promoted.Code)
	}

	// Demoting the creator is fine while bob is admin; removing the final
	// admin must be rejected.
	demoted := doJSON(t, handler, http.MethodPatch, base+"/alice", aliceSession, `{"role":"org:viewer"}`, nil)
	if demoted.Code != http.StatusOK {
		t.Fatalf("demote alice while bob is admin: %d %s", demoted.Code, demoted.Body.String())
	}
	// bob is now the only admin; alice (viewer) cannot demote bob, and even
	// bob cannot demote himself as the last admin.
	forbidden := doJSON(t, handler, http.MethodPatch, base+"/bob", aliceSession, `{"role":"org:member"}`, nil)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("viewer must not manage members, got %d", forbidden.Code)
	}

	removedSelf := doJSON(t, handler, http.MethodDelete, base+"/alice", aliceSession, "", nil)
	if removedSelf.Code != http.StatusNoContent {
		t.Fatalf("member should be able to leave: %d", removedSelf.Code)
	}
}

func TestPlatformOrgNeverSurfacesAsTenant(t *testing.T) {
	service, directory, store := newTestService(t)
	sessionID := seedSession(t, store, "alice")
	handler := routerFor(service)

	// A system-level authorization on the platform organization (for example
	// system-admin) must not appear in "my organizations"…
	directory.organizations["platform-org"] = "ZITADEL"
	directory.nextID++
	directory.authorizations["authz-platform"] = zitadel.Authorization{
		ID: "authz-platform", UserID: "alice", OrganizationID: "platform-org",
		Roles: []string{"system-admin"}, State: "STATE_ACTIVE",
	}

	listed := doJSON(t, handler, http.MethodGet, "/api/account/orgs", sessionID, "", nil)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), "platform-org") {
		t.Fatalf("platform org must not be listed as a tenant: %d %s", listed.Code, listed.Body.String())
	}

	// …and must not be a valid switch target.
	switched := doJSON(t, handler, http.MethodPost, "/api/auth/context", sessionID, `{"organizationId":"platform-org"}`, nil)
	if switched.Code != http.StatusNotFound {
		t.Fatalf("switching to the platform org must 404, got %d", switched.Code)
	}
}

func TestIdentityFacadeRequiresToken(t *testing.T) {
	service, directory, _ := newTestService(t)
	directory.users["u1"] = zitadel.User{ID: "u1", LoginName: "u1@shiguang", DisplayName: "U One", Email: "u1@example.com"}
	handler := routerFor(service)

	denied := doJSON(t, handler, http.MethodPost, "/v1/identity/users/batch-get", "", `{"ids":["u1"]}`, nil)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("missing token should 401, got %d", denied.Code)
	}

	allowed := doJSON(t, handler, http.MethodPost, "/v1/identity/users/batch-get", "", `{"ids":["u1"]}`, map[string]string{
		"Authorization": "Bearer " + strings.Repeat("i", 40),
	})
	if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), "U One") {
		t.Fatalf("batch get users: %d %s", allowed.Code, allowed.Body.String())
	}
}

func TestPointsIdentitySearchIsMinimalActiveOnlyAndFailClosed(t *testing.T) {
	service, directory, _ := newTestService(t)
	directory.users["active"] = zitadel.User{
		ID: "active", LoginName: "alice@shiguang", DisplayName: "Alice", Email: "alice@example.com", State: "USER_STATE_ACTIVE",
	}
	directory.users["disabled"] = zitadel.User{
		ID: "disabled", LoginName: "alice-disabled@shiguang", DisplayName: "Alice Disabled", Email: "disabled@example.com", State: "USER_STATE_INACTIVE",
	}
	handler := routerFor(service)

	wrongToken := doJSON(t, handler, http.MethodPost, "/v1/identity/users/search", "", `{"query":"alice","limit":10}`, map[string]string{
		"Authorization": "Bearer " + strings.Repeat("i", 40),
	})
	if wrongToken.Code != http.StatusUnauthorized {
		t.Fatalf("general identity token must not authorize Points search: %d", wrongToken.Code)
	}

	for name, body := range map[string]string{
		"short query":   `{"query":"al","limit":10}`,
		"zero limit":    `{"query":"alice","limit":0}`,
		"large limit":   `{"query":"alice","limit":11}`,
		"unknown field": `{"query":"alice","limit":10,"email":true}`,
		"trailing json": `{"query":"alice","limit":10} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			response := doJSON(t, handler, http.MethodPost, "/v1/identity/users/search", "", body, map[string]string{
				"Authorization": "Bearer " + strings.Repeat("p", 40),
			})
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
		})
	}

	allowed := doJSON(t, handler, http.MethodPost, "/v1/identity/users/search", "", `{"query":"alice","limit":10}`, map[string]string{
		"Authorization": "Bearer " + strings.Repeat("p", 40),
	})
	if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), `"id":"active"`) {
		t.Fatalf("search active users: %d %s", allowed.Code, allowed.Body.String())
	}
	if strings.Contains(allowed.Body.String(), "disabled") || strings.Contains(allowed.Body.String(), "example.com") || strings.Contains(allowed.Body.String(), "email") {
		t.Fatalf("search leaked inactive user or unnecessary PII: %s", allowed.Body.String())
	}

	directory.searchErr = errors.New("directory unavailable")
	failed := doJSON(t, handler, http.MethodPost, "/v1/identity/users/search", "", `{"query":"alice","limit":10}`, map[string]string{
		"Authorization": "Bearer " + strings.Repeat("p", 40),
	})
	if failed.Code != http.StatusServiceUnavailable {
		t.Fatalf("directory failure must fail closed: %d %s", failed.Code, failed.Body.String())
	}
}

func TestPointsIdentityResolveRequiresDedicatedTokenAndActiveExactID(t *testing.T) {
	service, directory, _ := newTestService(t)
	directory.users["active"] = zitadel.User{
		ID: "active", LoginName: "alice@shiguang", DisplayName: "Alice", Email: "alice@example.com", State: "USER_STATE_ACTIVE",
	}
	directory.users["disabled"] = zitadel.User{
		ID: "disabled", LoginName: "disabled@shiguang", DisplayName: "Disabled", Email: "disabled@example.com", State: "USER_STATE_INACTIVE",
	}
	handler := routerFor(service)

	wrongToken := doJSON(t, handler, http.MethodPost, "/v1/identity/users/resolve", "", `{"userId":"active"}`, map[string]string{
		"Authorization": "Bearer " + strings.Repeat("i", 40),
	})
	if wrongToken.Code != http.StatusUnauthorized {
		t.Fatalf("general identity token must not authorize Points resolve: %d", wrongToken.Code)
	}

	active := doJSON(t, handler, http.MethodPost, "/v1/identity/users/resolve", "", `{"userId":"active"}`, map[string]string{
		"Authorization": "Bearer " + strings.Repeat("p", 40),
	})
	if active.Code != http.StatusOK || !strings.Contains(active.Body.String(), `"id":"active"`) {
		t.Fatalf("resolve active user: %d %s", active.Code, active.Body.String())
	}
	if strings.Contains(active.Body.String(), "example.com") || strings.Contains(active.Body.String(), "email") {
		t.Fatalf("resolve leaked unnecessary PII: %s", active.Body.String())
	}

	disabled := doJSON(t, handler, http.MethodPost, "/v1/identity/users/resolve", "", `{"userId":"disabled"}`, map[string]string{
		"Authorization": "Bearer " + strings.Repeat("p", 40),
	})
	if disabled.Code != http.StatusNotFound {
		t.Fatalf("disabled user must not resolve: %d %s", disabled.Code, disabled.Body.String())
	}
}

func TestPointsIdentitySearchRateLimit(t *testing.T) {
	service, _, _ := newTestService(t)
	service.searchLimit = 1
	handler := routerFor(service)
	headers := map[string]string{"Authorization": "Bearer " + strings.Repeat("p", 40)}
	first := doJSON(t, handler, http.MethodPost, "/v1/identity/users/search", "", `{"query":"alice","limit":1}`, headers)
	second := doJSON(t, handler, http.MethodPost, "/v1/identity/users/search", "", `{"query":"alice","limit":1}`, headers)
	if first.Code != http.StatusOK || second.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limit statuses = %d, %d", first.Code, second.Code)
	}
}

func TestMutationsRejectForeignOrigin(t *testing.T) {
	service, _, store := newTestService(t)
	sessionID := seedSession(t, store, "alice")
	handler := routerFor(service)

	request := httptest.NewRequest(http.MethodPost, "/api/account/orgs", strings.NewReader(`{"name":"org"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://evil.example.com")
	request.AddCookie(&http.Cookie{Name: "__Secure-sg_session", Value: sessionID})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("foreign origin must be rejected, got %d", recorder.Code)
	}
}

func itoa(value int) string {
	return strconv.Itoa(value)
}
