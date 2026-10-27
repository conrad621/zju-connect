package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/mythologyli/zju-connect/client/authchallenge"
	"github.com/mythologyli/zju-connect/log"
	"github.com/pquerna/otp/totp"
)

type tokenResponse struct {
	Code    int          `json:"code"`
	Message string       `json:"message"`
	Data    authStepData `json:"data"`
}

func (s *Session) completeTOTP(step authStep) (authStep, error) {
	response := authchallenge.CodeResponse{}
	if s.totpSecret != "" {
		var err error
		response.Code, err = totp.GenerateCode(s.totpSecret, time.Now())
		if err != nil {
			return authStep{}, fmt.Errorf("generate TOTP token: %w", err)
		}
	} else {
		challenge := authchallenge.CodeChallenge{
			Kind:                 authchallenge.CodeTOTP,
			Message:              "Please enter the TOTP token:",
			CanSkipSecondaryAuth: true,
		}
		var err error
		response, err = s.challengeHandler.HandleCodeChallenge(challenge)
		if err != nil {
			return authStep{}, fmt.Errorf("complete TOTP challenge: %w", err)
		}
	}

	skipSecondaryAuth := "0"
	if response.SkipSecondaryAuth {
		skipSecondaryAuth = "1"
	}
	payload := map[string]interface{}{
		"action":            "auth",
		"taskId":            newTaskID(),
		"totpToken":         response.Code,
		"isPrevEffect":      false,
		"skipSecondaryAuth": skipSecondaryAuth,
	}
	return s.submitToken(step.AuthID, payload)
}

func (s *Session) completeCustomToken(step authStep) (authStep, error) {
	challenge := authchallenge.CodeChallenge{
		Kind:                 authchallenge.CodeTOTP,
		Message:              "Please enter the TOTP token:",
		CanSkipSecondaryAuth: true,
	}
	response, err := s.challengeHandler.HandleCodeChallenge(challenge)
	if err != nil {
		return authStep{}, fmt.Errorf("complete custom token challenge: %w", err)
	}

	skipSecondaryAuth := "0"
	if response.SkipSecondaryAuth {
		skipSecondaryAuth = "1"
	}
	payload := map[string]interface{}{
		"code":              response.Code,
		"skipSecondaryAuth": skipSecondaryAuth,
		"taskId":            newTaskID(),
	}
	return s.submitToken(step.AuthID, payload)
}

func (s *Session) completeRadius(service string, step authStep) (authStep, error) {
	challenge := authchallenge.CodeChallenge{
		Kind:                 authchallenge.CodeRadius,
		Message:              "Please enter the RADIUS token:",
		CanSkipSecondaryAuth: true,
	}
	response, err := s.challengeHandler.HandleCodeChallenge(challenge)
	if err != nil {
		return authStep{}, fmt.Errorf("complete RADIUS challenge: %w", err)
	}

	// aTrust requires the RADIUS token RSA-encrypted on /auth/challenge, like the password.
	payload := map[string]interface{}{}
	if service == "auth/challenge" {
		encryptedToken, err := s.encryptChallengeResponse(response.Code)
		if err != nil {
			return authStep{}, fmt.Errorf("encrypt RADIUS token: %w", err)
		}
		payload["radiusToken"] = encryptedToken
		// Omit skipSecondaryAuth: an extra field makes aTrust reject with error 75500000.
	} else {
		payload["radiusToken"] = response.Code
		payload["skipSecondaryAuth"] = boolToInt(response.SkipSecondaryAuth)
	}
	s.addUsername(payload)
	return s.submitTokenAt(service, step.AuthID, payload)
}

func (s *Session) addUsername(payload map[string]interface{}) {
	if s.username != "" {
		payload["username"] = s.username
	}
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func formEncode(payload map[string]interface{}) []byte {
	form := url.Values{}
	for key, value := range payload {
		var s string
		switch v := value.(type) {
		case string:
			s = v
		case bool:
			s = strconv.FormatBool(v)
		default:
			s = fmt.Sprintf("%v", v)
		}
		if s != "" {
			form.Set(key, s)
		}
	}
	return []byte(form.Encode())
}

func newTaskID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return hex.EncodeToString(b)
}

func (s *Session) submitToken(authID string, payload map[string]interface{}) (authStep, error) {
	return s.submitTokenAt("auth/token", authID, payload)
}

func (s *Session) submitTokenAt(service string, authID string, payload map[string]interface{}) (authStep, error) {
	if service != "auth/token" && service != "auth/challenge" {
		return authStep{}, fmt.Errorf("unsupported token authentication service: %s", service)
	}

	if authID != "" {
		payload["authId"] = authID
	}

	postBody := formEncode(payload)

	path := "/passport/v1/" + service
	log.Printf("Perform POST %s", path)
	u := s.baseURL + path
	req, err := http.NewRequest("POST", u+"?"+WithSharedParams(nil).Encode(), bytes.NewReader(postBody))
	if err != nil {
		return authStep{}, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return authStep{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return authStep{}, err
	}
	log.DebugPrintf("Received token authentication: %s", string(body))

	var result tokenResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return authStep{}, err
	}
	if result.Code != 0 {
		return authStep{}, fmt.Errorf("token authentication failed with code %d: %s", result.Code, result.Message)
	}
	return authStepFromData(result.Data), nil
}

func (s *Session) accessCheck() (authStep, error) {
	log.Println("Perform GET /passport/v1/auth/accessCheck")
	u := s.baseURL + "/passport/v1/auth/accessCheck"
	req, err := http.NewRequest("GET", u+"?"+WithSharedParams(nil).Encode(), nil)
	if err != nil {
		return authStep{}, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return authStep{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return authStep{}, err
	}
	log.DebugPrintf("Received access check: %s", string(body))

	var result tokenResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return authStep{}, err
	}
	if result.Code != 0 {
		return authStep{}, fmt.Errorf("accessCheck failed with code %d: %s", result.Code, result.Message)
	}
	return authStepFromData(result.Data), nil
}
