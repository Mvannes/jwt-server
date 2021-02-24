package main

import (
	"jwt-server/jwt"
	"jwt-server/key"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

func Routes() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)

	r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hoi"))
	})

	r.Mount("/key", key.Routes())
	r.Mount("/jwt", jwt.Routes())

	return r
}

func initKeys() error {
	km := key.ProvideKeyManager()
	_, err := km.FetchLatestKeyVersion()

	if nil == err {
		return nil
	}
	if err == key.KeyNotFound {
		err = km.CreateKeyPair()
	}
	return err

}

func main() {
	err := initKeys()
	if nil != err {
		log.Fatal(err)
	}
	r := Routes()
	log.Fatal(http.ListenAndServe(":8081", r))

}
