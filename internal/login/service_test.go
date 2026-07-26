package login

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shiguanglab/auth-service/internal/config"
	"github.com/shiguanglab/auth-service/internal/session"
	"github.com/shiguanglab/auth-service/internal/zitadel"
)

func TestContextCreatesServerSideDirectLoginTransaction(t *testing.T) {
	service, transactions, _, _ := newDirectLoginTestService()
	request := httptest.NewRequest(http.MethodPost, "/api/auth/login/context", strings.NewReader(`{"returnTo":"/app/sichen?tab=recent"}`))
	request.Header.Set("Origin", "https://shiguanglab.com")
	response := httptest.NewRecorder()

	service.Context(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		TransactionID string `json:"transactionId"`
		CSRFToken     string `json:"csrfToken"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.TransactionID == "" || body.CSRFToken == "" {
		t.Fatalf("context = %#v", body)
	}
	attempt, ok := transactions.attempts[body.TransactionID]
	if !ok || attempt.ReturnTo != "/app/sichen?tab=recent" || attempt.CSRFToken != body.CSRFToken {
		t.Fatalf("stored attempt = %#v", attempt)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != csrfCookieName || !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatalf("cookies = %#v", cookies)
	}
}

func TestContextRejectsCrossOriginRequest(t *testing.T) {
	service, transactions, _, _ := newDirectLoginTestService()
	request := httptest.NewRequest(http.MethodPost, "/api/auth/login/context", strings.NewReader(`{"returnTo":"/app/sichen"}`))
	request.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()

	service.Context(response, request)

	if response.Code != http.StatusForbidden || len(transactions.attempts) != 0 {
		t.Fatalf("status = %d attempts=%d", response.Code, len(transactions.attempts))
	}
}

func TestContextNormalizesExternalReturnTarget(t *testing.T) {
	service, transactions, _, _ := newDirectLoginTestService()
	request := httptest.NewRequest(http.MethodPost, "/api/auth/login/context", strings.NewReader(`{"returnTo":"https://attacker.example/callback"}`))
	request.Header.Set("Origin", "https://shiguanglab.com")
	response := httptest.NewRecorder()

	service.Context(response, request)

	var body struct {
		TransactionID string `json:"transactionId"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if got := transactions.attempts[body.TransactionID].ReturnTo; got != "/" {
		t.Fatalf("returnTo = %q", got)
	}
}

func TestContextAcceptsAllowlistedFirstPartyReturnOrigin(t *testing.T) {
	service, transactions, _, _ := newDirectLoginTestService()
	request := httptest.NewRequest(http.MethodPost, "/api/auth/login/context", strings.NewReader(`{"returnTo":"https://opc.shiguanglab.com/workspaces?view=mine"}`))
	request.Header.Set("Origin", "https://shiguanglab.com")
	response := httptest.NewRecorder()

	service.Context(response, request)

	var body struct {
		TransactionID string `json:"transactionId"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if got := transactions.attempts[body.TransactionID].ReturnTo; got != "https://opc.shiguanglab.com/workspaces?view=mine" {
		t.Fatalf("returnTo = %q", got)
	}
}

func TestLoginLocationReturnsToOriginalAllowlistedProduct(t *testing.T) {
	service, _, _, _ := newDirectLoginTestService()
	location := service.LoginLocation("https", "opc.shiguanglab.com", "/workspaces")
	if location != "https://shiguanglab.com/login?return_to=https%3A%2F%2Fopc.shiguanglab.com%2Fworkspaces" {
		t.Fatalf("location = %q", location)
	}
}

func TestPasswordCreatesOpaquePlatformSessionWithoutOIDCCallback(t *testing.T) {
	service, transactions, upstream, sessions := newDirectLoginTestService()
	transactions.attempts["transaction"] = loginAttempt{
		CSRFToken: "csrf-token",
		ReturnTo:  "/app/sichen",
		CreatedAt: time.Now().UTC(),
	}
	upstream.passwordSession = zitadel.Session{
		ID:          "zitadel-session",
		Token:       "zitadel-session-token",
		Subject:     "zitadel-user",
		LoginName:   "alice@example.com",
		DisplayName: "Alice",
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/login/password",
		strings.NewReader(`{"transactionId":"transaction","loginName":"alice@example.com","password":"correct horse","csrfToken":"csrf-token"}`),
	)
	request.Header.Set("Origin", "https://shiguanglab.com")
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	response := httptest.NewRecorder()

	service.Password(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["redirect"] != "/app/sichen" {
		t.Fatalf("redirect = %q", body["redirect"])
	}
	if upstream.loginName != "alice@example.com" || upstream.password != "correct horse" {
		t.Fatalf("upstream credentials = %q / %q", upstream.loginName, upstream.password)
	}
	if _, ok := transactions.attempts["transaction"]; ok {
		t.Fatal("login transaction was not consumed")
	}

	var platformCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == "__Secure-sg_session" {
			platformCookie = cookie
		}
	}
	if platformCookie == nil || platformCookie.Value == "" || !platformCookie.HttpOnly || !platformCookie.Secure {
		t.Fatalf("platform cookie = %#v", platformCookie)
	}
	value, err := sessions.Get(context.Background(), platformCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if value.Subject != "zitadel-user" ||
		value.PreferredUsername != "alice@example.com" ||
		value.UpstreamSessionID != "zitadel-session" ||
		value.UpstreamSessionToken != "zitadel-session-token" ||
		len(value.AuthenticationMethods) != 1 ||
		value.AuthenticationMethods[0] != "pwd" {
		t.Fatalf("platform session = %#v", value)
	}
}

func TestPasswordRejectsCSRFBeforeCallingZITADEL(t *testing.T) {
	service, transactions, upstream, _ := newDirectLoginTestService()
	transactions.attempts["transaction"] = loginAttempt{
		CSRFToken: "expected",
		ReturnTo:  "/",
		CreatedAt: time.Now().UTC(),
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/login/password",
		strings.NewReader(`{"transactionId":"transaction","loginName":"alice","password":"secret","csrfToken":"tampered"}`),
	)
	request.Header.Set("Origin", "https://shiguanglab.com")
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "tampered"})
	response := httptest.NewRecorder()

	service.Password(response, request)

	if response.Code != http.StatusForbidden || upstream.calls != 0 {
		t.Fatalf("status = %d upstream calls=%d", response.Code, upstream.calls)
	}
}

func TestRegisterCreatesUnverifiedZITADELUser(t *testing.T) {
	service, transactions, upstream, _ := newDirectLoginTestService()
	transactions.attempts["registration"] = loginAttempt{
		CSRFToken: "csrf-token",
		ReturnTo:  "/login",
		CreatedAt: time.Now().UTC(),
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/register",
		strings.NewReader(`{"transactionId":"registration","csrfToken":"csrf-token","username":"alice_01","email":"ALICE@example.com","password":"Password123"}`),
	)
	request.Header.Set("Origin", "https://shiguanglab.com")
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	response := httptest.NewRecorder()

	service.Register(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if upstream.createdUsername != "alice_01" || upstream.createdEmail != "alice@example.com" ||
		upstream.createdPassword != "Password123" {
		t.Fatalf("created user = %q / %q", upstream.createdUsername, upstream.createdEmail)
	}
	if _, ok := transactions.attempts["registration"]; ok {
		t.Fatal("registration transaction was not consumed")
	}
}

func TestRegisterMapsDuplicateUserToConflict(t *testing.T) {
	service, transactions, upstream, _ := newDirectLoginTestService()
	transactions.attempts["registration"] = loginAttempt{
		CSRFToken: "csrf-token",
		CreatedAt: time.Now().UTC(),
	}
	upstream.err = &zitadel.APIError{StatusCode: http.StatusConflict}
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/auth/register",
		strings.NewReader(`{"transactionId":"registration","csrfToken":"csrf-token","username":"alice_01","email":"alice@example.com","password":"Password123"}`),
	)
	request.Header.Set("Origin", "https://shiguanglab.com")
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	response := httptest.NewRecorder()

	service.Register(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
}

func newDirectLoginTestService() (*Service, *fakeTransactionRepository, *fakeZitadelSessionClient, *session.MemoryStore) {
	transactions := &fakeTransactionRepository{attempts: make(map[string]loginAttempt)}
	upstream := &fakeZitadelSessionClient{}
	sessions := session.NewMemoryStore()
	return &Service{
		cfg: config.Config{
			PublicOrigin:        "https://shiguanglab.com",
			SessionCookieName:   "__Secure-sg_session",
			SessionCookieDomain: ".shiguanglab.com",
			AbsoluteTTL:         7 * 24 * time.Hour,
			IdleTTL:             12 * time.Hour,
			AllowedReturnOrigins: []string{
				"https://shiguanglab.com",
				"https://opc.shiguanglab.com",
			},
			DefaultEntitlements: []string{"superagents:access"},
		},
		sessions:     sessions,
		transactions: transactions,
		zitadel:      upstream,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, transactions, upstream, sessions
}

type fakeTransactionRepository struct {
	mu           sync.Mutex
	attempts     map[string]loginAttempt
	transactions map[string]transaction
}

func (f *fakeTransactionRepository) putTransaction(_ context.Context, value transaction) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.transactions == nil {
		f.transactions = make(map[string]transaction)
	}
	f.transactions[value.State] = value
	return nil
}

func (f *fakeTransactionRepository) getTransaction(_ context.Context, id string) (transaction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, ok := f.transactions[id]
	if !ok {
		return transaction{}, errTransactionNotFound
	}
	return value, nil
}

func (f *fakeTransactionRepository) deleteTransaction(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.transactions, id)
	return nil
}

func (f *fakeTransactionRepository) putAttempt(_ context.Context, id string, value loginAttempt) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts[id] = value
	return nil
}

func (f *fakeTransactionRepository) takeAttempt(_ context.Context, id string) (loginAttempt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, ok := f.attempts[id]
	if !ok {
		return loginAttempt{}, errTransactionNotFound
	}
	delete(f.attempts, id)
	return value, nil
}

func (f *fakeTransactionRepository) allowAttempt(context.Context, string) (bool, error) {
	return true, nil
}

func (f *fakeTransactionRepository) ping(context.Context) error {
	return nil
}

func (f *fakeTransactionRepository) close() error {
	return nil
}

type fakeZitadelSessionClient struct {
	passwordSession zitadel.Session
	err             error
	calls           int
	loginName       string
	password        string
	createdUsername string
	createdEmail    string
	createdPassword string
}

func (f *fakeZitadelSessionClient) PasswordSession(_ context.Context, loginName, password string) (zitadel.Session, error) {
	f.calls++
	f.loginName = loginName
	f.password = password
	if f.err != nil {
		return zitadel.Session{}, f.err
	}
	return f.passwordSession, nil
}

func (f *fakeZitadelSessionClient) DeleteSession(context.Context, string, string) error {
	return nil
}

func (f *fakeZitadelSessionClient) CreateHumanUser(_ context.Context, username, email, password string) (zitadel.CreatedUser, error) {
	f.calls++
	f.createdUsername = username
	f.createdEmail = email
	f.createdPassword = password
	if f.err != nil {
		return zitadel.CreatedUser{}, f.err
	}
	return zitadel.CreatedUser{ID: "created-user"}, nil
}

var _ transactionRepository = (*fakeTransactionRepository)(nil)
var _ zitadelSessionClient = (*fakeZitadelSessionClient)(nil)
