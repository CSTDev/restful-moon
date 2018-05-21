package main

import (
	"log"
	"net/http"

	"github.com/cstdev/restful-moon/router"
	"github.com/rs/cors"
)

func setupGlobalMiddleware(handler http.Handler) http.Handler {
	handleCORS := cors.Default().Handler
	return handleCORS(handler)
}

func main() {
	router := router.NewRouter()
	log.Fatal(http.ListenAndServe(":8000", setupGlobalMiddleware(router)))
}
