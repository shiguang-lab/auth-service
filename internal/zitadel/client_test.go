package zitadel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetUserByIDParsesCanonicalHumanProfile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v2/users" {
			t.Fatalf("request=%s %s", request.Method, request.URL.Path)
		}
		var body struct {
			Queries []map[string]struct {
				UserIDs []string `json:"userIds"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Queries) != 1 || len(body.Queries[0]["inUserIdsQuery"].UserIDs) != 1 ||
			body.Queries[0]["inUserIdsQuery"].UserIDs[0] != "user-1" {
			t.Fatalf("queries=%#v", body.Queries)
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{
			"result":[{
				"userId":"user-1",
				"preferredLoginName":"alice@example.com",
				"state":"USER_STATE_ACTIVE",
				"human":{
					"profile":{"displayName":"Alice Zhang","givenName":"Alice","familyName":"Zhang","nickName":"Ali","preferredLanguage":"zh-CN","gender":"GENDER_FEMALE"},
					"email":{"email":"alice@example.com","isVerified":true},
					"phone":{"phone":"+8613800000000","isVerified":false}
				}
			}]
		}`))
	}))
	defer server.Close()

	client := &Client{baseURL: server.URL, host: "sso.example.com", pat: "test-token", http: server.Client()}
	user, err := client.GetUserByID(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != "user-1" || user.LoginName != "alice@example.com" || user.DisplayName != "Alice Zhang" ||
		user.GivenName != "Alice" || user.FamilyName != "Zhang" || user.NickName != "Ali" ||
		user.PreferredLanguage != "zh-CN" || user.Gender != "GENDER_FEMALE" ||
		user.Email != "alice@example.com" || !user.EmailVerified ||
		user.Phone != "+8613800000000" || user.PhoneVerified || user.State != "USER_STATE_ACTIVE" {
		t.Fatalf("user=%#v", user)
	}
}

func TestEmailOTPSessionUsesEmailQueryChallengeAndRotatedToken(t *testing.T) {
	step := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		step++
		response.Header().Set("Content-Type", "application/json")
		switch step {
		case 1:
			if request.Method != http.MethodPost || request.URL.Path != "/v2/users" {
				t.Fatalf("request=%s %s", request.Method, request.URL.Path)
			}
			var body struct {
				Queries []struct {
					EmailQuery struct {
						EmailAddress string `json:"emailAddress"`
						Method       string `json:"method"`
					} `json:"emailQuery"`
				} `json:"queries"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body.Queries) != 1 || body.Queries[0].EmailQuery.EmailAddress != "alice@example.com" ||
				body.Queries[0].EmailQuery.Method != "TEXT_QUERY_METHOD_EQUALS_IGNORE_CASE" {
				t.Fatalf("queries=%#v", body.Queries)
			}
			_, _ = response.Write([]byte(`{"result":[{"userId":"user-1","preferredLoginName":"alice","human":{"email":{"email":"alice@example.com"}}}]}`))
		case 2:
			if request.Method != http.MethodPost || request.URL.Path != "/v2/users/user-1/otp_email" {
				t.Fatalf("request=%s %s", request.Method, request.URL.Path)
			}
			response.WriteHeader(http.StatusConflict)
			_, _ = response.Write([]byte(`{"code":6,"message":"OTP already set"}`))
		case 3:
			if request.Method != http.MethodPost || request.URL.Path != "/v2/sessions" {
				t.Fatalf("request=%s %s", request.Method, request.URL.Path)
			}
			var body struct {
				Checks struct {
					User struct {
						UserID string `json:"userId"`
					} `json:"user"`
				} `json:"checks"`
				Challenges struct {
					OTPEmail struct {
						SendCode struct {
							URLTemplate string `json:"urlTemplate"`
						} `json:"sendCode"`
					} `json:"otpEmail"`
				} `json:"challenges"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Checks.User.UserID != "user-1" ||
				body.Challenges.OTPEmail.SendCode.URLTemplate != "https://example.com/email/callback?code={{.Code}}" {
				t.Fatalf("body=%#v", body)
			}
			_, _ = response.Write([]byte(`{"sessionId":"otp-session","sessionToken":"initial-token"}`))
		case 4:
			if request.Method != http.MethodPatch || request.URL.Path != "/v2/sessions/otp-session" ||
				request.Header.Get("Authorization") != "Bearer test-token" {
				t.Fatalf("request=%s %s auth=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
			}
			var body struct {
				Checks struct {
					OTPEmail struct {
						Code string `json:"code"`
					} `json:"otpEmail"`
				} `json:"checks"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Checks.OTPEmail.Code != "12345678" {
				t.Fatalf("body=%#v", body)
			}
			_, _ = response.Write([]byte(`{"sessionToken":"rotated-token"}`))
		case 5:
			if request.Method != http.MethodGet || request.URL.Path != "/v2/sessions/otp-session" ||
				request.Header.Get("Authorization") != "Bearer rotated-token" {
				t.Fatalf("request=%s %s auth=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
			}
			_, _ = response.Write([]byte(`{"session":{"factors":{"user":{"id":"user-1","loginName":"alice","displayName":"Alice"}}}}`))
		default:
			t.Fatalf("unexpected request=%s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()

	client := &Client{baseURL: server.URL, host: "sso.example.com", pat: "test-token", http: server.Client()}
	challenge, err := client.StartEmailOTP(
		context.Background(),
		"alice@example.com",
		"https://example.com/email/callback?code={{.Code}}",
	)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.SessionID != "otp-session" || challenge.SessionToken != "initial-token" {
		t.Fatalf("challenge=%#v", challenge)
	}
	verified, err := client.VerifyEmailOTP(context.Background(), challenge.SessionID, "12345678")
	if err != nil {
		t.Fatal(err)
	}
	if verified.Subject != "user-1" || verified.Token != "rotated-token" || verified.LoginName != "alice" || step != 5 {
		t.Fatalf("verified=%#v step=%d", verified, step)
	}
}
