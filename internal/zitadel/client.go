package zitadel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Client struct {
	baseURL         string
	host            string
	pat             string
	registrationPAT string
	organizationID  string
	http            *http.Client
}

type Session struct {
	ID          string
	Token       string
	Subject     string
	LoginName   string
	DisplayName string
}

type createSessionResponse struct {
	SessionID    string `json:"sessionId"`
	SessionToken string `json:"sessionToken"`
}

type getSessionResponse struct {
	Session struct {
		Factors struct {
			User struct {
				ID          string `json:"id"`
				LoginName   string `json:"loginName"`
				DisplayName string `json:"displayName"`
			} `json:"user"`
		} `json:"factors"`
	} `json:"session"`
}

type CreatedUser struct {
	ID string
}

type Organization struct {
	ID   string
	Name string
}

type Authorization struct {
	ID             string
	UserID         string
	OrganizationID string
	Roles          []string
	State          string
	DisplayName    string
	LoginName      string
}

type User struct {
	ID          string
	LoginName   string
	DisplayName string
	Email       string
	State       string
}

type IDPLink struct {
	IDPID    string
	UserID   string
	UserName string
}

type IDPInformation struct {
	IDPID        string
	UserID       string
	UserName     string
	LinkedUserID string
	Email        string
	DisplayName  string
}

type APIError struct {
	StatusCode int
}

func (e *APIError) Error() string {
	return fmt.Sprintf("ZITADEL request failed with status %d", e.StatusCode)
}

func NewClient(baseURL, publicIssuer, patFile, registrationPATFile, organizationID string) (*Client, error) {
	pat, err := os.ReadFile(patFile)
	if err != nil {
		return nil, fmt.Errorf("read ZITADEL login client PAT: %w", err)
	}
	registrationPAT, err := os.ReadFile(registrationPATFile)
	if err != nil {
		return nil, fmt.Errorf("read ZITADEL registration client PAT: %w", err)
	}
	issuerURL, err := url.Parse(publicIssuer)
	if err != nil || issuerURL.Host == "" {
		return nil, errors.New("invalid ZITADEL issuer")
	}
	return &Client{
		baseURL:         strings.TrimRight(baseURL, "/"),
		host:            issuerURL.Host,
		pat:             strings.TrimSpace(string(pat)),
		registrationPAT: strings.TrimSpace(string(registrationPAT)),
		organizationID:  strings.TrimSpace(organizationID),
		http:            &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (c *Client) PasswordSession(ctx context.Context, loginName, password string) (Session, error) {
	body := map[string]any{
		"checks": map[string]any{
			"user":     map[string]string{"loginName": loginName},
			"password": map[string]string{"password": password},
		},
	}
	var created createSessionResponse
	if err := c.do(ctx, http.MethodPost, "/v2/sessions", c.pat, body, &created); err != nil {
		return Session{}, err
	}

	var current getSessionResponse
	if err := c.do(ctx, http.MethodGet, "/v2/sessions/"+url.PathEscape(created.SessionID), created.SessionToken, nil, &current); err != nil {
		return Session{}, err
	}
	return Session{
		ID:          created.SessionID,
		Token:       created.SessionToken,
		Subject:     current.Session.Factors.User.ID,
		LoginName:   current.Session.Factors.User.LoginName,
		DisplayName: current.Session.Factors.User.DisplayName,
	}, nil
}

func (c *Client) DeleteSession(ctx context.Context, id, token string) error {
	if id == "" || token == "" {
		return nil
	}
	return c.do(ctx, http.MethodDelete, "/v2/sessions/"+url.PathEscape(id), token, nil, nil)
}

// StartIdentityProviderIntent starts ZITADEL's authenticated external-identity flow.
// The intent callback returns a short-lived token that must be retrieved before linking.
func (c *Client) StartIdentityProviderIntent(ctx context.Context, idpID, successURL, failureURL string) (string, error) {
	body := map[string]any{
		"idpId": idpID,
		"urls": map[string]string{
			"successUrl": successURL,
			"failureUrl": failureURL,
		},
	}
	var started struct {
		AuthURL string `json:"authUrl"`
	}
	if err := c.do(ctx, http.MethodPost, "/v2/idp_intents", c.pat, body, &started); err != nil {
		return "", err
	}
	if started.AuthURL == "" {
		return "", errors.New("ZITADEL IDP intent did not return an auth URL")
	}
	return started.AuthURL, nil
}

func (c *Client) RetrieveIdentityProviderIntent(ctx context.Context, intentID, intentToken string) (IDPInformation, error) {
	body := map[string]string{
		"idpIntentId":    intentID,
		"idpIntentToken": intentToken,
	}
	var retrieved struct {
		IDPInformation struct {
			IDPID    string `json:"idpId"`
			UserID   string `json:"userId"`
			UserName string `json:"userName"`
		} `json:"idpInformation"`
		UserID       string `json:"userId"`
		AddHumanUser struct {
			Username string `json:"username"`
			Profile  struct {
				GivenName   string `json:"givenName"`
				FamilyName  string `json:"familyName"`
				DisplayName string `json:"displayName"`
			} `json:"profile"`
			Email struct {
				Email string `json:"email"`
			} `json:"email"`
		} `json:"addHumanUser"`
		CreateUser struct {
			Username string `json:"username"`
			Human    struct {
				Profile struct {
					GivenName   string `json:"givenName"`
					FamilyName  string `json:"familyName"`
					DisplayName string `json:"displayName"`
				} `json:"profile"`
				Email struct {
					Email string `json:"email"`
				} `json:"email"`
			} `json:"human"`
		} `json:"createUser"`
	}
	if err := c.do(ctx, http.MethodPost, "/v2/idp_intents/"+url.PathEscape(intentID), c.pat, body, &retrieved); err != nil {
		return IDPInformation{}, err
	}
	info := IDPInformation{
		IDPID:        retrieved.IDPInformation.IDPID,
		UserID:       retrieved.IDPInformation.UserID,
		UserName:     retrieved.IDPInformation.UserName,
		LinkedUserID: retrieved.UserID,
		Email:        retrieved.AddHumanUser.Email.Email,
		DisplayName:  retrieved.AddHumanUser.Profile.DisplayName,
	}
	if info.DisplayName == "" {
		info.DisplayName = strings.TrimSpace(retrieved.AddHumanUser.Profile.GivenName + " " + retrieved.AddHumanUser.Profile.FamilyName)
	}
	if info.Email == "" {
		info.Email = retrieved.CreateUser.Human.Email.Email
	}
	if info.DisplayName == "" {
		info.DisplayName = retrieved.CreateUser.Human.Profile.DisplayName
	}
	if info.DisplayName == "" {
		info.DisplayName = strings.TrimSpace(retrieved.CreateUser.Human.Profile.GivenName + " " + retrieved.CreateUser.Human.Profile.FamilyName)
	}
	return info, nil
}

func (c *Client) AddIDPLink(ctx context.Context, userID string, link IDPLink) error {
	body := map[string]any{
		"userId": userID,
		"idpLink": map[string]string{
			"idpId":    link.IDPID,
			"userId":   link.UserID,
			"userName": link.UserName,
		},
	}
	return c.do(ctx, http.MethodPost, "/v2/users/"+url.PathEscape(userID)+"/links", c.pat, body, nil)
}

func (c *Client) ListIDPLinks(ctx context.Context, userID string) ([]IDPLink, error) {
	var found struct {
		Result []struct {
			IDPID    string `json:"idpId"`
			UserID   string `json:"userId"`
			UserName string `json:"userName"`
		} `json:"result"`
	}
	if err := c.do(ctx, http.MethodPost, "/v2/users/"+url.PathEscape(userID)+"/links/_search", c.pat, map[string]any{}, &found); err != nil {
		return nil, err
	}
	links := make([]IDPLink, 0, len(found.Result))
	for _, item := range found.Result {
		links = append(links, IDPLink{IDPID: item.IDPID, UserID: item.UserID, UserName: item.UserName})
	}
	return links, nil
}

func (c *Client) CreateHumanUser(ctx context.Context, username, email, password string) (CreatedUser, error) {
	return c.createHumanUser(ctx, username, email, password, nil)
}

func (c *Client) CreateHumanUserWithIDPLink(
	ctx context.Context,
	username, email, password string,
	link IDPLink,
) (CreatedUser, error) {
	return c.createHumanUser(ctx, username, email, password, &link)
}

func (c *Client) createHumanUser(ctx context.Context, username, email, password string, link *IDPLink) (CreatedUser, error) {
	human := map[string]any{
		"profile": map[string]string{
			"givenName":   username,
			"familyName":  username,
			"displayName": username,
		},
		"email": map[string]any{
			"email":    email,
			"sendCode": map[string]any{},
		},
		"password": map[string]any{
			"password":       password,
			"changeRequired": false,
		},
	}
	if link != nil {
		human["idpLinks"] = []map[string]string{{
			"idpId":    link.IDPID,
			"userId":   link.UserID,
			"userName": link.UserName,
		}}
	}
	body := map[string]any{
		"organizationId": c.organizationID,
		"username":       username,
		"human":          human,
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/v2/users/new", c.registrationPAT, body, &created); err != nil {
		return CreatedUser{}, err
	}
	if created.ID == "" {
		return CreatedUser{}, errors.New("ZITADEL create user response does not include an id")
	}
	return CreatedUser{ID: created.ID}, nil
}

// CreateOrganization creates a business organization owned by the platform.
func (c *Client) CreateOrganization(ctx context.Context, name string) (Organization, error) {
	var created struct {
		OrganizationID string `json:"organizationId"`
		ID             string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/v2/organizations", c.pat, map[string]any{"name": name}, &created); err != nil {
		return Organization{}, err
	}
	id := created.OrganizationID
	if id == "" {
		id = created.ID
	}
	if id == "" {
		return Organization{}, errors.New("ZITADEL create organization response does not include an id")
	}
	return Organization{ID: id, Name: name}, nil
}

// SearchOrganizationsByIDs resolves organization names for the given ids.
func (c *Client) SearchOrganizationsByIDs(ctx context.Context, ids []string) ([]Organization, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	organizations := make([]Organization, 0, len(ids))
	for _, chunk := range chunkStrings(ids, 50) {
		queries := make([]map[string]any, 0, len(chunk))
		for _, id := range chunk {
			queries = append(queries, map[string]any{"idQuery": map[string]string{"id": id}})
		}
		var found struct {
			Result []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
		}
		if err := c.do(ctx, http.MethodPost, "/v2/organizations/_search", c.pat, map[string]any{"queries": queries}, &found); err != nil {
			return nil, err
		}
		for _, item := range found.Result {
			organizations = append(organizations, Organization{ID: item.ID, Name: item.Name})
		}
	}
	return organizations, nil
}

// EnsureProjectRole creates a project role, tolerating roles that already exist.
func (c *Client) EnsureProjectRole(ctx context.Context, projectID, roleKey, displayName string) error {
	body := map[string]any{"roleKey": roleKey, "displayName": displayName}
	err := c.doWithOrg(ctx, http.MethodPost, "/management/v1/projects/"+url.PathEscape(projectID)+"/roles", c.pat, c.organizationID, body, nil)
	var apiError *APIError
	if errors.As(err, &apiError) && (apiError.StatusCode == http.StatusConflict || apiError.StatusCode == http.StatusBadRequest) {
		return nil
	}
	return err
}

// EnsureProjectGrant grants the platform project to a business organization so
// that authorizations can be created on it. Existing grants are tolerated.
func (c *Client) EnsureProjectGrant(ctx context.Context, projectID, grantedOrgID string, roleKeys []string) error {
	body := map[string]any{"grantedOrgId": grantedOrgID, "roleKeys": roleKeys}
	err := c.doWithOrg(ctx, http.MethodPost, "/management/v1/projects/"+url.PathEscape(projectID)+"/grants", c.pat, c.organizationID, body, nil)
	var apiError *APIError
	if errors.As(err, &apiError) && apiError.StatusCode == http.StatusConflict {
		return nil
	}
	return err
}

// CreateAuthorization grants project roles to a user on a business organization.
func (c *Client) CreateAuthorization(ctx context.Context, userID, projectID, organizationID string, roleKeys []string) (string, error) {
	body := map[string]any{
		"userId":         userID,
		"projectId":      projectID,
		"organizationId": organizationID,
		"roleKeys":       roleKeys,
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/v2beta/authorizations", c.pat, body, &created); err != nil {
		return "", err
	}
	return created.ID, nil
}

// UpdateAuthorization replaces the role keys of an authorization.
func (c *Client) UpdateAuthorization(ctx context.Context, id string, roleKeys []string) error {
	return c.do(ctx, http.MethodPatch, "/v2beta/authorizations/"+url.PathEscape(id), c.pat, map[string]any{"roleKeys": roleKeys}, nil)
}

// DeleteAuthorization removes an authorization.
func (c *Client) DeleteAuthorization(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v2beta/authorizations/"+url.PathEscape(id), c.pat, nil, nil)
}

type AuthorizationFilter struct {
	UserID         string
	OrganizationID string
	ProjectID      string
	ActiveOnly     bool
}

// ListAuthorizations searches authorizations by user and/or organization.
func (c *Client) ListAuthorizations(ctx context.Context, filter AuthorizationFilter) ([]Authorization, error) {
	filters := make([]map[string]any, 0, 4)
	if filter.UserID != "" {
		filters = append(filters, map[string]any{"userId": map[string]string{"id": filter.UserID}})
	}
	if filter.OrganizationID != "" {
		filters = append(filters, map[string]any{"organizationId": map[string]string{"id": filter.OrganizationID}})
	}
	if filter.ProjectID != "" {
		filters = append(filters, map[string]any{"projectId": map[string]string{"id": filter.ProjectID}})
	}
	if filter.ActiveOnly {
		filters = append(filters, map[string]any{"state": map[string]string{"state": "STATE_ACTIVE"}})
	}
	body := map[string]any{
		"pagination": map[string]any{"limit": 500},
		"filters":    filters,
	}
	var found struct {
		Authorizations []struct {
			ID             string   `json:"id"`
			OrganizationID string   `json:"organizationId"`
			Roles          []string `json:"roles"`
			State          string   `json:"state"`
			User           struct {
				ID                 string `json:"id"`
				PreferredLoginName string `json:"preferredLoginName"`
				DisplayName        string `json:"displayName"`
			} `json:"user"`
		} `json:"authorizations"`
	}
	if err := c.do(ctx, http.MethodPost, "/v2beta/authorizations/search", c.pat, body, &found); err != nil {
		return nil, err
	}
	authorizations := make([]Authorization, 0, len(found.Authorizations))
	for _, item := range found.Authorizations {
		authorizations = append(authorizations, Authorization{
			ID:             item.ID,
			UserID:         item.User.ID,
			OrganizationID: item.OrganizationID,
			Roles:          append([]string(nil), item.Roles...),
			State:          item.State,
			DisplayName:    item.User.DisplayName,
			LoginName:      item.User.PreferredLoginName,
		})
	}
	return authorizations, nil
}

// GetUserByLoginName resolves one user by an exact login name.
func (c *Client) GetUserByLoginName(ctx context.Context, loginName string) (User, error) {
	body := map[string]any{
		"queries": []map[string]any{
			{"loginNameQuery": map[string]any{"loginName": loginName, "method": "TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE"}},
		},
	}
	users, err := c.searchUsers(ctx, body)
	if err != nil {
		return User{}, err
	}
	if len(users) == 0 {
		return User{}, &APIError{StatusCode: http.StatusNotFound}
	}
	return users[0], nil
}

// SearchUsersByIDs resolves display information for the given user ids.
func (c *Client) SearchUsersByIDs(ctx context.Context, ids []string) ([]User, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	users := make([]User, 0, len(ids))
	for _, chunk := range chunkStrings(ids, 100) {
		body := map[string]any{
			"queries": []map[string]any{
				{"inUserIdsQuery": map[string]any{"userIds": chunk}},
			},
		}
		found, err := c.searchUsers(ctx, body)
		if err != nil {
			return nil, err
		}
		users = append(users, found...)
	}
	return users, nil
}

// SearchUsers performs two bounded, non-PII directory searches so callers can
// find users by login or display name without gaining access to email fields.
func (c *Client) SearchUsers(ctx context.Context, query string, limit int) ([]User, error) {
	methods := []string{"loginNameQuery", "displayNameQuery"}
	users := make([]User, 0, limit)
	seen := make(map[string]struct{}, limit)
	for _, queryType := range methods {
		queryValue := map[string]any{"method": "TEXT_QUERY_METHOD_CONTAINS_IGNORE_CASE"}
		if queryType == "loginNameQuery" {
			queryValue["loginName"] = query
		} else {
			queryValue["displayName"] = query
		}
		body := map[string]any{
			"pagination": map[string]any{"limit": limit},
			"queries":    []map[string]any{{queryType: queryValue}},
		}
		found, err := c.searchUsers(ctx, body)
		if err != nil {
			return nil, err
		}
		for _, user := range found {
			if _, exists := seen[user.ID]; exists {
				continue
			}
			seen[user.ID] = struct{}{}
			users = append(users, user)
			if len(users) == limit {
				return users, nil
			}
		}
	}
	return users, nil
}

func (c *Client) searchUsers(ctx context.Context, body map[string]any) ([]User, error) {
	var found struct {
		Result []struct {
			UserID             string `json:"userId"`
			PreferredLoginName string `json:"preferredLoginName"`
			State              string `json:"state"`
			Human              struct {
				Profile struct {
					DisplayName string `json:"displayName"`
				} `json:"profile"`
				Email struct {
					Email string `json:"email"`
				} `json:"email"`
			} `json:"human"`
		} `json:"result"`
	}
	if err := c.do(ctx, http.MethodPost, "/v2/users", c.pat, body, &found); err != nil {
		return nil, err
	}
	users := make([]User, 0, len(found.Result))
	for _, item := range found.Result {
		users = append(users, User{
			ID:          item.UserID,
			LoginName:   item.PreferredLoginName,
			DisplayName: item.Human.Profile.DisplayName,
			Email:       item.Human.Email.Email,
			State:       item.State,
		})
	}
	return users, nil
}

func (c *Client) doWithOrg(ctx context.Context, method, path, bearer, orgID string, body, result any) error {
	return c.request(ctx, method, path, bearer, orgID, body, result)
}

func (c *Client) do(ctx context.Context, method, path, bearer string, body, result any) error {
	return c.request(ctx, method, path, bearer, "", body, result)
}

func chunkStrings(values []string, size int) [][]string {
	var chunks [][]string
	for start := 0; start < len(values); start += size {
		end := start + size
		if end > len(values) {
			end = len(values)
		}
		chunks = append(chunks, values[start:end])
	}
	return chunks
}

func (c *Client) request(ctx context.Context, method, path, bearer, orgID string, body, result any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode ZITADEL request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("create ZITADEL request: %w", err)
	}
	request.Host = c.host
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Forwarded-Proto", "https")
	if orgID != "" {
		request.Header.Set("x-zitadel-orgid", orgID)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("call ZITADEL: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read ZITADEL response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &APIError{StatusCode: response.StatusCode}
	}
	if result != nil && len(responseBody) > 0 {
		if err := json.Unmarshal(responseBody, result); err != nil {
			return fmt.Errorf("decode ZITADEL response: %w", err)
		}
	}
	return nil
}

type RewriteTransport struct {
	IssuerURL   *url.URL
	InternalURL *url.URL
	Base        http.RoundTripper
}

func NewRewriteHTTPClient(publicIssuer, internalURL string) (*http.Client, error) {
	issuer, err := url.Parse(publicIssuer)
	if err != nil {
		return nil, fmt.Errorf("parse ZITADEL issuer: %w", err)
	}
	internal, err := url.Parse(internalURL)
	if err != nil {
		return nil, fmt.Errorf("parse ZITADEL internal URL: %w", err)
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &RewriteTransport{
			IssuerURL:   issuer,
			InternalURL: internal,
			Base:        http.DefaultTransport,
		},
	}, nil
}

func (t *RewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	clone.URL = cloneURL(request.URL)
	if clone.URL.Host == t.IssuerURL.Host {
		clone.URL.Scheme = t.InternalURL.Scheme
		clone.URL.Host = t.InternalURL.Host
		clone.Host = t.IssuerURL.Host
		clone.Header.Set("X-Forwarded-Proto", "https")
	}
	return t.Base.RoundTrip(clone)
}

func cloneURL(value *url.URL) *url.URL {
	cloned := *value
	return &cloned
}
