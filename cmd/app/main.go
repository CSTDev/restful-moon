package main

import (
	"net/http"

	"github.com/cstdev/restful-moon/moonboard"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
)

func setupGlobalMiddleware(handler http.Handler) http.Handler {
	handleCORS := cors.Default().Handler
	return handleCORS(handler)
}

func main() {
	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.InfoLevel)

	sessionBuilder := &moonboard.WebServiceSession{}
	var service = &moonboard.WebService{SessionBuilder: sessionBuilder}

	router := moonboard.NewRouter(service)

	port := "8000"
	log.WithField("port", port).Info("Starting server")
	log.Fatal(http.ListenAndServe(":"+port, setupGlobalMiddleware(router)))
}
