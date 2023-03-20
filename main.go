package main

import (
	"github.com/mvannes/jwt-server/user"
	"log"
	"net/http"
	"time"

	"github.com/mvannes/jwt-server/config"
	"github.com/mvannes/jwt-server/jwk"
	"github.com/mvannes/jwt-server/jwt"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func Routes(config config.Config) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)

	r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	r.Mount("/jwk", jwk.Routes(config))
	r.Mount("/jwt", jwt.Routes(config))
	r.Mount("/users", user.Routes(config))

	return r
}

func initKeys() error {
	// TODO: Requires me to make a keys dir by hand now.
	// Configure it, and change this to not require manual intervention.
	km := jwk.NewKeyManager()
	_, err := km.FetchLatestKeyVersion()

	if nil == err {
		return nil
	}
	if err == jwk.KeyNotFound {
		err = km.CreateKeyPair()
	}
	return err

}

func main() {
	c := config.Config{
		DomainName:     "localhost:8080",
		JWKLocationURL: "/",
	}
	err := initKeys()
	if nil != err {
		log.Fatal(err)
	}
	r := Routes(c)

	log.Fatal(http.ListenAndServe(":8080", r))

}
