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

func (c *Client) CreateHumanUser(ctx context.Context, username, email, password string) (CreatedUser, error) {
	body := map[string]any{
		"organizationId": c.organizationID,
		"username":       username,
		"human": map[string]any{
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
		},
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

func (c *Client) do(ctx context.Context, method, path, bearer string, body, result any) error {
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
