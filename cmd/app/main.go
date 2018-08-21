package main

import (
	"net/http"
	"os"
	"strings"

	"github.com/cstdev/restful-moon/moonboard"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
)

func setupGlobalMiddleware(handler http.Handler) http.Handler {
	handleCORS := cors.Default().Handler
	return handleCORS(handler)
}

func main() {

	logLevel := os.Getenv("LOG_LEVEL")
	secret := os.Getenv("JWT_SECRET")

	log.SetFormatter(&log.JSONFormatter{})

	switch strings.ToUpper(logLevel) {
	case "DEBUG":
		log.SetLevel(log.DebugLevel)
		break
	case "ERROR":
		log.SetLevel(log.ErrorLevel)
		break
	default:
		log.SetLevel(log.InfoLevel)
	}

	log.WithField("Secret", secret).Debug("JWT_SECRET")
	if secret == "" {
		log.Error("JWT_SECRET env variable not set, required for signing JWTs")
		os.Exit(1)
	}

	sessionBuilder := &moonboard.WebServiceSession{}
	var service = &moonboard.WebService{JWTSecret: secret, SessionBuilder: sessionBuilder}

	router := moonboard.NewRouter(service)

	port := "8000"
	log.WithField("port", port).Info("Starting server")
	log.Fatal(http.ListenAndServe(":"+port, setupGlobalMiddleware(router)))
}
