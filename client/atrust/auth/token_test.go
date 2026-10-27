package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mythologyli/zju-connect/client/authchallenge"
)

func TestAuthStepFromTokenService(t *testing.T) {
	step := authStepFromData(authStepData{
		NextService: "auth/token",
		NextServiceList: []authServiceInfo{{
			AuthID:   "totp-id",
			AuthType: "auth/totp",
		}},
	})
	if step.Service != "auth/totp" || step.AuthID != "totp-id" {
		t.Fatalf("unexpected token step: %+v", step)
	}

	// bilibili-style gateways describe the second factor as
	// authType=auth/token with subType=https and authName=TOTP, which aTrust
	// routes to the custom-token flow (field "code").
	step = authStepFromData(authStepData{
		NextService: "auth/token",
		NextServiceList: []authServiceInfo{{
			AuthID:   "totp-id",
			AuthType: "auth/token",
			SubType:  "https",
			AuthName: "TOTP",
		}},
	})
	if step.Service != "auth/customToken" || step.AuthID != "totp-id" {
		t.Fatalf("unexpected https token step: %+v", step)
	}

	step = authStepFromData(authStepData{NextService: "auth/sendSms"})
	if step.Service != "auth/sms" || step.SMSMode != smsWithoutAuthID {
		t.Fatalf("unexpected sendSms step: %+v", step)
	}
}

func TestSubmitTOTPToken(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/passport/v1/auth/token" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("authId") != "" {
			t.Errorf("authId must be sent in the body, not the URL: %s", r.URL.RawQuery)
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("username") != "user@domain" || r.Form.Get("action") != "auth" || r.Form.Get("totpToken") != "123456" || r.Form.Get("isPrevEffect") != "false" || r.Form.Get("authId") != "totp-id" || r.Form.Get("skipSecondaryAuth") != "0" {
			t.Errorf("unexpected payload: %+v", r.Form)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"code":0,"data":{"nextService":"auth/accessCheck"}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	session.username = "user@domain"
	step, err := session.submitToken("totp-id", map[string]interface{}{
		"username":          session.username,
		"action":            "auth",
		"totpToken":         "123456",
		"isPrevEffect":      false,
		"skipSecondaryAuth": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Service != "auth/accessCheck" {
		t.Fatalf("unexpected next step: %+v", step)
	}
}

func TestCompleteTOTPUsesStructuredChallengeResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("totpToken") != "123456" || r.Form.Get("skipSecondaryAuth") != "1" {
			t.Errorf("unexpected payload: %+v", r.Form)
		}
		fmt.Fprint(w, `{"code":0,"data":{}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	session.challengeHandler = authchallenge.HandlerFuncs{
		Code: func(challenge authchallenge.CodeChallenge) (authchallenge.CodeResponse, error) {
			if challenge.Kind != authchallenge.CodeTOTP || !challenge.CanSkipSecondaryAuth {
				t.Fatalf("unexpected challenge: %+v", challenge)
			}
			return authchallenge.CodeResponse{Code: "123456", SkipSecondaryAuth: true}, nil
		},
	}
	if _, err := session.completeTOTP(authStep{}); err != nil {
		t.Fatal(err)
	}
}

func TestCompleteCustomTokenUsesCodeField(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/passport/v1/auth/token" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("code") != "123456" || r.Form.Get("skipSecondaryAuth") != "1" || r.Form.Get("authId") != "token-id" {
			t.Errorf("unexpected payload: %+v", r.Form)
		}
		if r.Form.Get("totpToken") != "" || r.Form.Get("action") != "" || r.Form.Get("isPrevEffect") != "" {
			t.Errorf("unexpected TOTP fields in custom token payload: %+v", r.Form)
		}
		fmt.Fprint(w, `{"code":0,"data":{}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	session.challengeHandler = authchallenge.HandlerFuncs{
		Code: func(challenge authchallenge.CodeChallenge) (authchallenge.CodeResponse, error) {
			if challenge.Kind != authchallenge.CodeTOTP || !challenge.CanSkipSecondaryAuth {
				t.Fatalf("unexpected challenge: %+v", challenge)
			}
			return authchallenge.CodeResponse{Code: "123456", SkipSecondaryAuth: true}, nil
		},
	}
	if _, err := session.completeCustomToken(authStep{AuthID: "token-id"}); err != nil {
		t.Fatal(err)
	}
}

func TestSubmitTokenAllowsSessionBoundIdentity(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("username") != "" {
			t.Errorf("session-bound token request unexpectedly included username: %+v", r.Form)
		}
		fmt.Fprint(w, `{"code":0,"data":{}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	payload := map[string]interface{}{"totpToken": "123456"}
	session.addUsername(payload)
	if _, err := session.submitToken("", payload); err != nil {
		t.Fatal(err)
	}
}

func TestSMSUsernameIsAvailableToTokenStep(t *testing.T) {
	session := &Session{}
	method := SMSLogin{Phone: "13800138000", Domain: "example"}
	session.username = smsUsername(method.Phone, method.Domain)

	payload := make(map[string]interface{})
	session.addUsername(payload)
	if got := payload["username"]; got != "13800138000@example" {
		t.Fatalf("SMS token username = %v, want 13800138000@example", got)
	}
}

func TestAccessCheck(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/passport/v1/auth/accessCheck" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		fmt.Fprint(w, `{"code":0,"data":{}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	step, err := session.accessCheck()
	if err != nil {
		t.Fatal(err)
	}
	if step.Service != "" {
		t.Fatalf("unexpected next step: %+v", step)
	}
}
