package moonboard

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cstdev/moonapi"
	"github.com/cstdev/moonapi/query"
	jwt "github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
)

const SIGNING_KEY = "MySuperSecretKey"

func TestMain(m *testing.M) {
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.JSONFormatter{})
	retCode := m.Run()
	os.Exit(retCode)
}

func ok(tb testing.TB, err error) {
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		log.WithFields(log.Fields{
			"file":  file,
			"line":  line,
			"error": err.Error(),
		}).Error("Unexpected error recieved")
		tb.FailNow()
	}
}

type mockSessionBuilder struct {
	NewFunc func(r *http.Request) moonapi.MoonBoardApi
}

func (sb *mockSessionBuilder) New(r *http.Request) moonapi.MoonBoardApi {
	return sb.NewFunc(r)
}

type mockMoonBoard struct {
	LoginFunc       func(username string, password string) error
	GetProblemsFunc func(query query.Query) (moonapi.MbResponse, error)
	GetAuthFunc     func() []moonapi.AuthToken
	SetAuthFunc     func(authTokens []moonapi.AuthToken)
}

func (mb mockMoonBoard) Login(username string, password string) error {
	return mb.LoginFunc(username, password)
}

func (mb mockMoonBoard) GetProblems(query query.Query) (moonapi.MbResponse, error) {
	return mb.GetProblemsFunc(query)
}

func (mb mockMoonBoard) Auth() []moonapi.AuthToken {
	return mb.GetAuthFunc()
}

func (mb mockMoonBoard) SetAuth(authTokens []moonapi.AuthToken) {
	mb.SetAuthFunc(authTokens)
}

func okGetAuth() []moonapi.AuthToken {
	var auth []moonapi.AuthToken
	moonAuth := moonapi.AuthToken{
		Name:  "_MoonBoard",
		Value: "sdffasdfhuwehr23fsf89fnsafd",
	}
	reqToken := moonapi.AuthToken{
		Name:  "__RequestVerificationToken",
		Value: "gjnrgerjgna23498erabkjbr239",
	}
	auth = append(auth, moonAuth)
	auth = append(auth, reqToken)
	return auth
}

func TestAuthenticationWithEmptyBodyReturnsBadRequest(t *testing.T) {
	sessionBuilder := mockSessionBuilder{}
	service := &WebService{JWTSecret: SIGNING_KEY, SessionBuilder: &sessionBuilder}

	req, err := http.NewRequest("POST", "/authorisation", nil)
	ok(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(service.Authorisation())
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status: %d \n Actual status: %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAuthenticationWithInvalidJSONReturnsBadRequest(t *testing.T) {
	sessionBuilder := mockSessionBuilder{}
	service := &WebService{JWTSecret: SIGNING_KEY, SessionBuilder: &sessionBuilder}

	req, err := http.NewRequest("POST", "/authorisation", bytes.NewBuffer([]byte(`{\"user\":\"test\",\"password:\"password1\"}`)))
	ok(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(service.Authorisation())
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status: %d \n Actual status: %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAuthorisationWithNoUsernameReturnsBadRequest(t *testing.T) {
	sessionBuilder := mockSessionBuilder{}
	service := &WebService{JWTSecret: SIGNING_KEY, SessionBuilder: &sessionBuilder}

	req, err := http.NewRequest("POST", "/authorisation", bytes.NewBuffer([]byte(`{"username":"","password":"password1"}`)))
	ok(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(service.Authorisation())
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status: %d \n Actual status: %d", http.StatusBadRequest, rr.Code)
	}
}

func TestAuthorisationWithNoPasswordReturnsBadRequest(t *testing.T) {
	sessionBuilder := mockSessionBuilder{}
	service := &WebService{JWTSecret: SIGNING_KEY, SessionBuilder: &sessionBuilder}

	req, err := http.NewRequest("POST", "/authorisation", bytes.NewBuffer([]byte(`{"username":"test"}`)))
	ok(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(service.Authorisation())
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status: %d \n Actual status: %d", http.StatusBadRequest, rr.Code)
	}
}

func TestLoginIsCalledWithAUsernameAndPassword(t *testing.T) {
	called := false
	var username string
	var password string

	sessionBuilder := mockSessionBuilder{}
	moonBoard := mockMoonBoard{
		LoginFunc: func(user string, pass string) error {
			log.WithFields(log.Fields{
				"username": user,
				"password": pass,
			}).Debug("LoginFunc")
			called = true
			username = user
			password = pass
			return nil
		},
		GetAuthFunc: func() []moonapi.AuthToken {
			return okGetAuth()
		},
	}
	service := &WebService{JWTSecret: SIGNING_KEY, SessionBuilder: &sessionBuilder, MoonBoard: &moonBoard}

	req, err := http.NewRequest("POST", "/authorisation", bytes.NewBuffer([]byte(`{"username":"test","password":"password1"}`)))
	ok(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(service.Authorisation())
	handler.ServeHTTP(rr, req)
	if !called {
		t.Error("Expected login method to be called")
		t.FailNow()
	}

	expectedUser := "test"
	expectedPass := "password1"
	if username != expectedUser || password != expectedPass {
		t.Errorf("Expected-Actual Username: \n %s-%s \n Expected-Actual Password: \n %s-%s", expectedUser, username, expectedPass, password)
	}
}

func TestAuthorisationReturnsAJWT(t *testing.T) {
	sessionBuilder := mockSessionBuilder{}
	moonBoard := mockMoonBoard{
		LoginFunc: func(username string, password string) error {
			return nil
		},
		GetAuthFunc: func() []moonapi.AuthToken {
			return okGetAuth()
		},
	}
	service := &WebService{JWTSecret: SIGNING_KEY, SessionBuilder: &sessionBuilder, MoonBoard: &moonBoard}

	req, err := http.NewRequest("POST", "/authorisation", bytes.NewBuffer([]byte(`{"username":"test","password":"password1"}`)))
	ok(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(service.Authorisation())
	handler.ServeHTTP(rr, req)
	log.WithFields(log.Fields{
		"token": rr.Result().Header.Get("auth_token"),
	}).Debug("Returned token")
	if rr.Result().Header.Get("auth_token") == "" {
		t.Error("No auth_token header returned")
	}

}

// Authentication Middleware
func TestNoBearerTokenReturnsBadRequest(t *testing.T) {
	service := &WebService{JWTSecret: SIGNING_KEY}
	req, err := http.NewRequest("GET", "/problems", nil)
	ok(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(service.IsAuthenticated(service.GetProblems()))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status: %d \n Actual status: %d", http.StatusBadRequest, rr.Code)
	}
}

func generateValidToken(t *testing.T) string {

	claims := CustomClaims{
		"asdfjfweoifneow283fnweo",
		"fjdflkjdf23weiojj23",
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 20).Unix(),
			Issuer:    "Test",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	mySigningKey := []byte("MySuperSecretKey") //TODO might have issues in tests as uses key in IsAuthenticated
	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		t.Errorf("failed to generate key for test")
	}
	return tokenString
}

func TestWithValidBearerTokenCallsGetProblems(t *testing.T) {
	called := false
	moonBoard := mockMoonBoard{
		GetProblemsFunc: func(query query.Query) (moonapi.MbResponse, error) {
			called = true
			return moonapi.MbResponse{}, nil
		},
		SetAuthFunc: func(auth []moonapi.AuthToken) {
			//do nothing
		},
	}

	service := &WebService{JWTSecret: SIGNING_KEY, MoonBoard: &moonBoard}
	req, err := http.NewRequest("GET", "/problems", nil)
	req.Header.Add("Authorisation", "Bearer "+generateValidToken(t))
	ok(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(service.IsAuthenticated(service.GetProblems()))
	handler.ServeHTTP(rr, req)

	if called != true {
		t.Error("Expected GetProblems to be called")
		t.FailNow()
	}

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status: %d \n Actual status: %d", http.StatusOK, rr.Code)
	}
}

func TestWithValidBearerTokenPutsAuthInMoonBoardSession(t *testing.T) {
	var localAuthMocked []moonapi.AuthToken
	moonBoard := mockMoonBoard{
		GetProblemsFunc: func(query query.Query) (moonapi.MbResponse, error) {
			return moonapi.MbResponse{}, nil
		},
		SetAuthFunc: func(auth []moonapi.AuthToken) {
			localAuthMocked = auth
		},
		GetAuthFunc: func() []moonapi.AuthToken {
			return localAuthMocked
		},
	}

	service := &WebService{JWTSecret: SIGNING_KEY, MoonBoard: &moonBoard}
	req, err := http.NewRequest("GET", "/problems", nil)
	req.Header.Add("Authorisation", "Bearer "+generateValidToken(t))
	ok(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(service.IsAuthenticated(service.GetProblems()))
	handler.ServeHTTP(rr, req)

	if len(service.MoonBoard.Auth()) != 2 {
		t.Errorf("Expected there to be %d auth tokens. \n Actual number of auth tokens %d", 2, len(service.MoonBoard.Auth()))
		t.FailNow()
	}

	if service.MoonBoard.Auth()[0].Value != "asdfjfweoifneow283fnweo" {
		t.Errorf("Expected token: %s \n Actual toke: %s", "asdfjfweoifneow283fnweo", service.MoonBoard.Auth()[0].Value)
	}
}

func TestExpiredAuthTokenReturnsExpired(t *testing.T) {
	expiredToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtb29uYm9hcmQiOiJzZGZmYXNkZmh1d2VocjIzZnNmODlmbnNhZmQiLCJSVlQiOiJnam5yZ2VyamduYTIzNDk4ZXJhYmtqYnIyMzkiLCJleHAiOjE1MzQ3NTQ1MzIsImlzcyI6IlJFU1RmdWxNb29uIn0.pdxvtX_EzNihx9L5-2D0ogyANs70koqSMEgLFMa2OLw"

	called := false
	moonBoard := mockMoonBoard{
		GetProblemsFunc: func(query query.Query) (moonapi.MbResponse, error) {
			called = true
			return moonapi.MbResponse{}, nil
		},
		SetAuthFunc: func(auth []moonapi.AuthToken) {
			//do nothing
		},
	}

	service := &WebService{JWTSecret: SIGNING_KEY, MoonBoard: &moonBoard}
	req, err := http.NewRequest("GET", "/problems", nil)
	req.Header.Add("Authorisation", "Bearer "+expiredToken)
	ok(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(service.IsAuthenticated(service.GetProblems()))
	handler.ServeHTTP(rr, req)

	if called {
		t.Errorf("Expected expired token to not call Get Problems")
		t.FailNow()
	}

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status: %d \n Actual status: %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestBadlyFormattedAuthTokenReturnsBadRequest(t *testing.T) {
	expiredToken := "eyJhbGciOiJIUzI1NikLInR5cCI6IXVCJ912.eyJtb29uYm9hcmQiOiJzZGZmYXNkZmh1d2VocjIzZnNmODlmbnNhZmQiLCJSVlQiOiJnam5yZ2VyamduYTIzNDk4ZXJhYmtqYnIyMzkiLCJleHAiOjE1MzQ3NTQ1MzIsImlzcyI6IlJFU1RmdWxNb29uIn0.pdxvtX_EzNihx9L5-2D0ogyANs70koqSMEgLFMa2OLw"

	called := false
	moonBoard := mockMoonBoard{
		GetProblemsFunc: func(query query.Query) (moonapi.MbResponse, error) {
			called = true
			return moonapi.MbResponse{}, nil
		},
		SetAuthFunc: func(auth []moonapi.AuthToken) {
			//do nothing
		},
	}

	service := &WebService{JWTSecret: SIGNING_KEY, MoonBoard: &moonBoard}
	req, err := http.NewRequest("GET", "/problems", nil)
	req.Header.Add("Authorisation", "Bearer "+expiredToken)
	ok(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(service.IsAuthenticated(service.GetProblems()))
	handler.ServeHTTP(rr, req)

	if called {
		t.Errorf("Expected expired token to not call Get Problems")
		t.FailNow()
	}

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status: %d \n Actual status: %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestNoSecretInServiceReturns500(t *testing.T) {
	expiredToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtb29uYm9hcmQiOiJzZGZmYXNkZmh1d2VocjIzZnNmODlmbnNhZmQiLCJSVlQiOiJnam5yZ2VyamduYTIzNDk4ZXJhYmtqYnIyMzkiLCJleHAiOjE1MzQ3NTQ1MzIsImlzcyI6IlJFU1RmdWxNb29uIn0.pdxvtX_EzNihx9L5-2D0ogyANs70koqSMEgLFMa2OLw"

	called := false
	moonBoard := mockMoonBoard{
		GetProblemsFunc: func(query query.Query) (moonapi.MbResponse, error) {
			called = true
			return moonapi.MbResponse{}, nil
		},
		SetAuthFunc: func(auth []moonapi.AuthToken) {
			//do nothing
		},
	}

	service := &WebService{MoonBoard: &moonBoard}
	req, err := http.NewRequest("GET", "/problems", nil)
	req.Header.Add("Authorisation", "Bearer "+expiredToken)
	ok(t, err)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(service.IsAuthenticated(service.GetProblems()))
	handler.ServeHTTP(rr, req)

	if called {
		t.Errorf("Expected not to call Get Problems where no secret is provides")
		t.FailNow()
	}

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status: %d \n Actual status: %d", http.StatusInternalServerError, rr.Code)
	}
}
