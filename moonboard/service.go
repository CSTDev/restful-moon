package moonboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"

	"github.com/cstdev/moonapi"
	"github.com/cstdev/moonapi/utils"
	log "github.com/sirupsen/logrus"
)

type ErrorResponse struct {
	Message string `json:"message"`
}

type Health struct {
	Service       bool   `json:"serviceUp"`
	Connection    bool   `json:"canConnect"`
	ConnectionErr string `json:"connectionError"`
}

type User struct {
	Username string
	Password string
}

// Service interface defining all methods expected of a Service
type Service interface {
	HealthCheck() http.HandlerFunc
	Authorisation() http.HandlerFunc
	GetProblems() http.HandlerFunc
}

type SessionBuilder interface {
	New(r *http.Request) moonapi.MoonBoard
}

type WebServiceSession struct{}

func (s *WebServiceSession) New(r *http.Request) moonapi.MoonBoard {
	var auth []moonapi.AuthToken
	moonAuth := moonapi.AuthToken{
		Name:  "_MoonBoard",
		Value: r.Header.Get("_Moonboard"),
	}
	reqToken := moonapi.AuthToken{
		Name:  "__RequestVerificationToken",
		Value: r.Header.Get("__RequestVerificationToken"),
	}
	auth = append(auth, moonAuth)
	auth = append(auth, reqToken)

	session := moonapi.MoonBoard{
		Auth: auth,
	}
	return session
}

// WebService used to connect to the moonboard website
type WebService struct {
	SessionBuilder SessionBuilder
	MoonBoard      moonapi.MoonBoardApi
}

var session moonapi.MoonBoard

// HealthCheck returns if the service is up and running.
func (s *WebService) HealthCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		workingConn, err := checkConnection()
		if err == nil {
			err = errors.New("")
		}
		health := &Health{
			Service:       true,
			Connection:    workingConn,
			ConnectionErr: err.Error(),
		}
		data, _ := json.Marshal(health)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}
}

func checkConnection() (bool, error) {
	//return utils.CheckConnection() //Need to do dep ensure to get latest moonapi
	return false, nil
}

// Authorisation takes login credentials, logs into MoonBoard.com
// and returns a JWT containing the required tokens as claims
// Path: /authorisation
// Method: POST
// Request body:
//	{
//		"username": "test"
//		"password": "password1"
//	}
// Response:
// Headers: auth_token - <your JWT>
func (s *WebService) Authorisation() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var user User
		if r.Body == nil {
			log.WithFields(log.Fields{
				"status":  http.StatusBadRequest,
				"message": "Empty body provided",
			}).Error("Failed to unmarshal user")
			w.WriteHeader(http.StatusBadRequest)
			resp, _ := json.Marshal(&ErrorResponse{Message: "Empty body provided"})
			w.Write(resp)
			return
		}

		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			log.WithFields(log.Fields{
				"status":  http.StatusBadRequest,
				"message": err.Error(),
			}).Error("Failed to unmarshal user")
			w.WriteHeader(http.StatusBadRequest)
			resp, _ := json.Marshal(&ErrorResponse{Message: err.Error()})
			w.Write(resp)
			return
		}

		if user.Username == "" || user.Password == "" {
			log.WithFields(log.Fields{
				"status": http.StatusBadRequest,
				"user":   user.Username,
			}).Error("Missing username or password")
			w.WriteHeader(http.StatusBadRequest)
			resp, _ := json.Marshal(&ErrorResponse{Message: "Missing username or password"})
			w.Write(resp)
			return
		}

		err = s.MoonBoard.Login(user.Username, user.Password)
		if err != nil {
			log.WithFields(log.Fields{
				"status":  http.StatusUnauthorized,
				"message": err.Error(),
			}).Error("unable to log in")
			w.WriteHeader(http.StatusUnauthorized)
			resp, _ := json.Marshal(&ErrorResponse{Message: err.Error()})
			w.Write(resp)
			return
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"MoonBoard": s.MoonBoard.GetAuth()[0],
			"RVT":       s.MoonBoard.GetAuth()[1],
		})

		mySigningKey := []byte("MySuperSecretKey") //TODO check if it matters what or where this is
		tokenString, err := token.SignedString(mySigningKey)
		if err != nil {
			log.WithFields(log.Fields{
				"status":  http.StatusUnauthorized,
				"message": err.Error(),
			}).Error("unable to log in")
			w.WriteHeader(http.StatusInternalServerError)
			resp, _ := json.Marshal(&ErrorResponse{Message: err.Error()})
			w.Write(resp)
			return
		}

		log.WithFields(log.Fields{
			"status":   http.StatusOK,
			"username": user.Username,
			"token":    tokenString,
		}).Info("Successful login")

		w.Header().Set("auth_token", tokenString)
		w.WriteHeader(http.StatusOK)
		w.Header()
		return
	}
}

// GetProblems returns the problems that match the query parameters
// passed in the request
// Path: /problems
// Method: GET
// URL Parameters:
//		q: search term, e.g. name of the problem
//		order: sort by new, grade, rating, repeats
//		asc: Sort by decending
//		configuration: Board configuration Forty, Twenty
//		holdSet: Hold Set types to include split by comma: OS, Wood, A, B, C. (default all)
//		filter: Filter to apply to problems: Benchmarks, Setbyme, Myascents
// 		minGrade: Mininum grade to return.
//		maxGrade: Maximum grade to return.
//		page: Page number
//		pageSize: Page size
// Returns:
//		JSON array containing problems
func (s *WebService) GetProblems() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error

		query := &utils.RequestQuery{
			Term:          r.URL.Query().Get("q"),
			Order:         r.URL.Query().Get("order"),
			Asc:           r.URL.Query().Get("asc"),
			Configuration: r.URL.Query().Get("configuration"),
			HoldSet:       r.URL.Query().Get("holdSet"),
			Filter:        r.URL.Query().Get("filter"),
			MinGrade:      r.URL.Query().Get("minGrade"),
			MaxGrade:      r.URL.Query().Get("maxGrade"),
			Page:          r.URL.Query().Get("page"),
			PageSize:      r.URL.Query().Get("pageSize"),
		}

		reqQuery, err := query.Query()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			resp, _ := json.Marshal(&ErrorResponse{Message: err.Error()})
			w.Write(resp)
			return
		}
		fmt.Println(reqQuery)
		session = s.SessionBuilder.New(r)
		problems, err := session.GetProblems(reqQuery)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			resp, _ := json.Marshal(&ErrorResponse{Message: err.Error()})
			w.Write(resp)
			return
		}

		resp, err := moonapi.ProblemsAsJSON(problems.Data)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			resp, _ := json.Marshal(&ErrorResponse{Message: err.Error()})
			w.Write(resp)
			return
		}
		w.Write([]byte(resp))
		return
	}
}
