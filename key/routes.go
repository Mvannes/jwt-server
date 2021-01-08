package key

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
)

func Routes() *chi.Mux {
	h := ProvideKeyHandler()
	r := chi.NewRouter()

	r.Get("/", h.GetLatestKeyVersion)
	r.Get("/{uuid}", h.GetSpecificKeyVersion)

	return r
}

type KeyHandler struct {
	KeyManager KeyManagerInterface
}

func ProvideKeyHandler() *KeyHandler {
	return &KeyHandler{KeyManager: ProvideKeyManager()}
}

func (h *KeyHandler) GetLatestKeyVersion(w http.ResponseWriter, r *http.Request) {
	latestKey, err := h.KeyManager.FetchLatestKeyVersion()
	if err != nil {
		if err == KeyNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.getKey(w, r, latestKey)
}

func (h *KeyHandler) GetSpecificKeyVersion(w http.ResponseWriter, r *http.Request) {
	jwtVersion := chi.URLParam(r, "uuid")
	h.getKey(w, r, jwtVersion)
}

func (h *KeyHandler) getKey(w http.ResponseWriter, r *http.Request, keyVersion string) {
	keyPair, err := h.KeyManager.FetchKeyPair(keyVersion)
	if err != nil {
		if err == KeyNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(keyPair.PublicKey),
	}
	render.PlainText(w, r, string(pem.EncodeToMemory(publicKeyBlock)))
}
