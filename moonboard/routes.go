package moonboard

import (
	"net/http"

	"github.com/gorilla/mux"
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

var routes []Route

func initRoutes(service Service) {
	routes = Routes{
		Route{
			"HealthCheck",
			"GET",
			"/",
			service.HealthCheck(),
		},
		Route{
			"GetProblems",
			"GET",
			"/problems",
			service.GetProblems(),
		},
	}
}

func NewRouter(s Service) *mux.Router {
	initRoutes(s)
	router := mux.NewRouter().StrictSlash(true)

	sub := router.PathPrefix("/v1").Subrouter()

	for _, route := range routes {
		sub.HandleFunc(route.Pattern, route.HandlerFunc).Name(route.Name).Methods(route.Method)
	}
	return router
}
