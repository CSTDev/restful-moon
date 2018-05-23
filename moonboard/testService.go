package moonboard

import (
	"net/http"
)

// TestService example of how to create one for testing
type TestService struct {
}

// GetProblems for testing
func (s *TestService) GetProblems() http.HandlerFunc {
	return nil
}

// HealthCheck for testing
func (s *TestService) HealthCheck() http.HandlerFunc {
	return nil
}
