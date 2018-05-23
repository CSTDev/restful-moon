package moonboard

import (
	"fmt"
	"net/http"
)

type Service interface {
	HealthCheck() http.HandlerFunc
	GetProblems() http.HandlerFunc
}

type WebService struct {
	DB *string
}

func (s *WebService) GetProblems() http.HandlerFunc {
	fmt.Printf("DB: %s", *s.DB)
	return func(w http.ResponseWriter, r *http.Request) {
		keys := r.URL.Query()
		page := keys["page"]
		fmt.Println(page)
	}
}

func (s *WebService) HealthCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}
