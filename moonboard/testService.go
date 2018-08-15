package moonboard

import (
	"net/http"
)

// TestService example of how to create one for testing
type TestService struct {
}

// Login for testing
func (s *TestService) Login() http.HandlerFunc {
	return nil
}

// GetProblems for testing
func (s *TestService) GetProblems() http.HandlerFunc {
	return nil
}

// HealthCheck for testing
func (s *TestService) HealthCheck() http.HandlerFunc {
	return nil
}
