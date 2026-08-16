package login

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shiguanglab/auth-service/internal/config"
	"github.com/shiguanglab/auth-service/internal/session"
	"github.com/shiguanglab/auth-service/internal/zitadel"
	"golang.org/x/oauth2"
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

func TestStartRejectsUnsupportedProviderBeforeOIDCDiscovery(t *testing.T) {
	service, transactions, _, _ := newDirectLoginTestService()
	request := httptest.NewRequest(http.MethodGet, "/api/auth/federated/start?provider=google&return_to=%2F", nil)
	response := httptest.NewRecorder()

	service.Start(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "unsupported_provider") {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	if len(transactions.transactions) != 0 {
		t.Fatalf("transactions = %#v", transactions.transactions)
	}
}

func TestStartUsesZITADELIdentityProviderIntent(t *testing.T) {
	service, transactions, upstream, _ := newDirectLoginTestService()
	service.cfg.OIDCProviderIDs = map[string]string{"github": "github-idp"}
	upstream.intentURL = "https://sso.example.com/idp/authorize"
	request := httptest.NewRequest(http.MethodGet, "/api/auth/federated/start?provider=github&return_to=%2Fworkspace", nil)
	response := httptest.NewRecorder()

	service.Start(response, request)

	if response.Code != http.StatusFound || response.Header().Get("Location") != upstream.intentURL {
		t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	if len(transactions.transactions) != 1 {
		t.Fatalf("transactions=%#v", transactions.transactions)
	}
	for _, value := range transactions.transactions {
		if !value.Federated || value.Provider != "github" || value.ReturnTo != "/workspace" {
			t.Fatalf("transaction=%#v", value)
		}
	}
}

func TestFederatedCallbackRedirectsNewIdentityToWebsiteRegistration(t *testing.T) {
	service, transactions, upstream, _ := newDirectLoginTestService()
	service.cfg.OIDCProviderIDs = map[string]string{"github": "github-idp"}
	transactions.transactions["state"] = transaction{State: "state", Federated: true, Provider: "github", ReturnTo: "/workspace"}
	upstream.intentInfo = zitadel.IDPInformation{IDPID: "github-idp", UserID: "external-user", UserName: "octocat", Email: "octo@example.com", DisplayName: "Octo Cat"}
	request := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/callback?state=state&idp_intent_id=intent&idp_intent_token=token", nil)
	response := httptest.NewRecorder()

	service.Callback(response, request)

	if response.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Path != "/register" || location.Query().Get("mode") != "federated" || location.Query().Get("transaction_id") == "" {
		t.Fatalf("location=%q", location.String())
	}
	pending, ok := transactions.federated[location.Query().Get("transaction_id")]
	if !ok || pending.ExternalUserID != "external-user" || pending.SuggestedEmail != "octo@example.com" {
		t.Fatalf("pending=%#v", pending)
	}
}

func TestFederatedRegistrationCreatesLinkedUserAndSession(t *testing.T) {
	service, transactions, upstream, sessions := newDirectLoginTestService()
	service.cfg.OIDCProviderIDs = map[string]string{"github": "github-idp"}
	transactions.federated["registration"] = federatedRegistration{
		TransactionID: "registration", CSRFToken: "csrf-token", Provider: "github", IDPID: "github-idp",
		ExternalUserID: "external-user", ExternalUserName: "octocat", SuggestedName: "Octo Cat", ReturnTo: "/workspace",
	}
	request := httptest.NewRequest(http.MethodPost, "/api/auth/register/federated", strings.NewReader(`{"transactionId":"registration","csrfToken":"csrf-token","username":"octo_01","email":"octo@example.com","password":"Password123"}`))
	request.Header.Set("Origin", "https://shiguanglab.com")
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	response := httptest.NewRecorder()

	service.RegisterFederated(response, request)

	if response.Code != http.StatusCreated || upstream.createdLink.UserID != "external-user" || upstream.createdLink.IDPID != "github-idp" {
		t.Fatalf("status=%d body=%s link=%#v", response.Code, response.Body.String(), upstream.createdLink)
	}
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["redirect"] != "/workspace" {
		t.Fatalf("body=%#v", body)
	}
	if _, ok := transactions.federated["registration"]; ok {
		t.Fatal("federated registration was not consumed")
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookies=%#v", cookies)
	}
	platformCookie := cookies[0]
	if platformCookie.Name != "__Secure-sg_session" {
		platformCookie = cookies[1]
	}
	if platformCookie.Value == "" {
		t.Fatal("session cookie is empty")
	}
	if value, err := sessions.Get(context.Background(), platformCookie.Value); err != nil || value.Subject != "created-user" {
		t.Fatalf("session=%#v err=%v", value, err)
	}
}

func TestOAuthConfigForProviderAddsZitadelSelectionScope(t *testing.T) {
	service, _, _, _ := newDirectLoginTestService()
	configured := oauth2.Config{Scopes: []string{"openid", "profile"}}
	selected, err := service.oauthConfigForProvider(configured, "github")
	if err != nil {
		t.Fatal(err)
	}
	values, err := url.ParseQuery(selected.AuthCodeURL("state"))
	if err != nil {
		t.Fatal(err)
	}
	if got := values.Get("scope"); got != "openid profile "+zitadelSelectIDPScope+"383564589272399875" {
		t.Fatalf("scope = %q", got)
	}
	if len(configured.Scopes) != 2 {
		t.Fatalf("original scopes mutated: %#v", configured.Scopes)
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

func TestCreateLocalBrokerStoresBrokerOnlyCredential(t *testing.T) {
	service, _, upstream, sessions := newDirectLoginTestService()
	upstream.passwordSession = zitadel.Session{
		ID:          "zitadel-broker-session",
		Token:       "zitadel-broker-token",
		Subject:     "zitadel-user",
		LoginName:   "alice@example.com",
		DisplayName: "Alice",
	}

	brokerToken, value, err := service.CreateLocalBroker(
		context.Background(), "127.0.0.1", "alice@example.com", "correct horse", 12*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if brokerToken == "" || value.CredentialKind != session.CredentialKindLocalBroker ||
		value.Subject != "zitadel-user" || value.CredentialExpiresAt.IsZero() {
		t.Fatalf("broker token=%q session=%#v", brokerToken, value)
	}
	stored, err := sessions.Get(context.Background(), brokerToken)
	if err != nil {
		t.Fatal(err)
	}
	if stored.UpstreamSessionToken != "zitadel-broker-token" || stored.PreferredUsername != "alice@example.com" {
		t.Fatalf("stored broker=%#v", stored)
	}
	resolved, err := service.ResolveLocalBroker(context.Background(), brokerToken)
	if err != nil || resolved.Subject != "zitadel-user" {
		t.Fatalf("resolved=%#v err=%v", resolved, err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	request.AddCookie(&http.Cookie{Name: "__Secure-sg_session", Value: brokerToken})
	response := httptest.NewRecorder()
	service.Session(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("broker accepted as browser session: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCreateLocalBrokerRejectsInvalidCredentialsWithoutPersisting(t *testing.T) {
	service, _, upstream, _ := newDirectLoginTestService()
	upstream.err = &zitadel.APIError{StatusCode: http.StatusUnauthorized}

	brokerToken, _, err := service.CreateLocalBroker(
		context.Background(), "127.0.0.1", "alice@example.com", "wrong", time.Hour,
	)
	if !errors.Is(err, ErrBrokerInvalidCredentials) || brokerToken != "" {
		t.Fatalf("token=%q err=%v", brokerToken, err)
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
	transactions := &fakeTransactionRepository{
		attempts:     make(map[string]loginAttempt),
		transactions: make(map[string]transaction),
		links:        make(map[string]linkTransaction),
		federated:    make(map[string]federatedRegistration),
	}
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
			OIDCProviderIDs:     map[string]string{"github": "383564589272399875"},
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
	links        map[string]linkTransaction
	federated    map[string]federatedRegistration
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

func (f *fakeTransactionRepository) putLinkTransaction(_ context.Context, value linkTransaction) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.links == nil {
		f.links = make(map[string]linkTransaction)
	}
	f.links[value.State] = value
	return nil
}

func (f *fakeTransactionRepository) getLinkTransaction(_ context.Context, id string) (linkTransaction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, ok := f.links[id]
	if !ok {
		return linkTransaction{}, errTransactionNotFound
	}
	return value, nil
}

func (f *fakeTransactionRepository) deleteLinkTransaction(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.links, id)
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

func (f *fakeTransactionRepository) putFederatedRegistration(_ context.Context, value federatedRegistration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.federated == nil {
		f.federated = make(map[string]federatedRegistration)
	}
	f.federated[value.TransactionID] = value
	return nil
}

func (f *fakeTransactionRepository) getFederatedRegistration(_ context.Context, id string) (federatedRegistration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, ok := f.federated[id]
	if !ok {
		return federatedRegistration{}, errTransactionNotFound
	}
	return value, nil
}

func (f *fakeTransactionRepository) takeFederatedRegistration(_ context.Context, id string) (federatedRegistration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, ok := f.federated[id]
	if !ok {
		return federatedRegistration{}, errTransactionNotFound
	}
	delete(f.federated, id)
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
	createdLink     zitadel.IDPLink
	intentURL       string
	intentInfo      zitadel.IDPInformation
	links           []zitadel.IDPLink
	addedUserID     string
	addedLink       zitadel.IDPLink
}

func (f *fakeZitadelSessionClient) ListAuthorizations(
	_ context.Context,
	_ zitadel.AuthorizationFilter,
) ([]zitadel.Authorization, error) {
	return nil, nil
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

func (f *fakeZitadelSessionClient) CreateHumanUserWithIDPLink(_ context.Context, username, email, password string, link zitadel.IDPLink) (zitadel.CreatedUser, error) {
	f.calls++
	f.createdUsername = username
	f.createdEmail = email
	f.createdPassword = password
	f.createdLink = link
	if f.err != nil {
		return zitadel.CreatedUser{}, f.err
	}
	return zitadel.CreatedUser{ID: "created-user"}, nil
}

func (f *fakeZitadelSessionClient) StartIdentityProviderIntent(context.Context, string, string, string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.intentURL, nil
}

func (f *fakeZitadelSessionClient) RetrieveIdentityProviderIntent(context.Context, string, string) (zitadel.IDPInformation, error) {
	if f.err != nil {
		return zitadel.IDPInformation{}, f.err
	}
	return f.intentInfo, nil
}

func (f *fakeZitadelSessionClient) AddIDPLink(_ context.Context, userID string, link zitadel.IDPLink) error {
	f.addedUserID = userID
	f.addedLink = link
	if f.err != nil {
		return f.err
	}
	f.links = append(f.links, link)
	return nil
}

func (f *fakeZitadelSessionClient) ListIDPLinks(context.Context, string) ([]zitadel.IDPLink, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]zitadel.IDPLink(nil), f.links...), nil
}

var _ transactionRepository = (*fakeTransactionRepository)(nil)
var _ zitadelSessionClient = (*fakeZitadelSessionClient)(nil)
