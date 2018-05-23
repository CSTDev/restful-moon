package moonboard

import (
	"net/http"
)

type TestService struct {
}

func (s *TestService) GetProblems() http.HandlerFunc {
	return nil
}

func (s *TestService) HealthCheck() http.HandlerFunc {
	return nil
}
