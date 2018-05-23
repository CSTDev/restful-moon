package moonboard

import (
	"fmt"
	"net/http"
)

// Service interface defining all methods expected of a Service
type Service interface {
	HealthCheck() http.HandlerFunc
	GetProblems() http.HandlerFunc
}

// WebService used to connect to the moonboard website
// TODO temporary DB is just an example
type WebService struct {
	DB *string
}

// HealthCheck returns if the service is up and running.
func (s *WebService) HealthCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

// GetProblems returns the problems that match the query parameters
// passed in the request
func (s *WebService) GetProblems() http.HandlerFunc {
	fmt.Printf("DB: %s", *s.DB)
	return func(w http.ResponseWriter, r *http.Request) {
		keys := r.URL.Query()
		page := keys["page"]
		fmt.Println(page)
	}
}
