package moonboard

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"

	"github.com/cstdev/moonapi"
	"github.com/cstdev/moonapi/query"
	log "github.com/sirupsen/logrus"
)

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
	NewFunc func(r *http.Request) moonapi.MoonBoard
}

func (sb *mockSessionBuilder) New(r *http.Request) moonapi.MoonBoard {
	return sb.NewFunc(r)
}

type mockMoonBoard struct {
	LoginFunc       func(username string, password string) error
	GetProblemsFunc func(query query.Query) (moonapi.MbResponse, error)
	GetAuthFunc     func() []moonapi.AuthToken
}

func (mb *mockMoonBoard) Login(username string, password string) error {
	return mb.LoginFunc(username, password)
}

func (mb *mockMoonBoard) GetProblems(query query.Query) (moonapi.MbResponse, error) {
	return mb.GetProblemsFunc(query)
}

func (mb *mockMoonBoard) GetAuth() []moonapi.AuthToken {
	return mb.GetAuthFunc()
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
	service := &WebService{SessionBuilder: &sessionBuilder}

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
	service := &WebService{SessionBuilder: &sessionBuilder}

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
	service := &WebService{SessionBuilder: &sessionBuilder}

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
	service := &WebService{SessionBuilder: &sessionBuilder}

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
	service := &WebService{SessionBuilder: &sessionBuilder, MoonBoard: &moonBoard}

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
	service := &WebService{SessionBuilder: &sessionBuilder, MoonBoard: &moonBoard}

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
