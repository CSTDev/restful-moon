package main

import (
	"log"
	"net/http"

	"github.com/cstdev/restful-moon/moonboard"
	"github.com/rs/cors"
)

func setupGlobalMiddleware(handler http.Handler) http.Handler {
	handleCORS := cors.Default().Handler
	return handleCORS(handler)
}

func main() {
	db := "mongo:\\\\"
	var service = &moonboard.WebService{DB: &db}

	router := moonboard.NewRouter(service)

	log.Fatal(http.ListenAndServe(":8000", setupGlobalMiddleware(router)))
}
