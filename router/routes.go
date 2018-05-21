package router

import (
	"net/http"

	handler "github.com/cstdev/restful-moon/handlers"
)

// Route type description
type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}

// Routes contains all routes
type Routes []Route

var routes = Routes{
	Route{
		"HealthCheck",
		"GET",
		"/",
		handler.HealthCheck,
	},
}
