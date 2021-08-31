package jwk

import (
	"encoding/base64"
	"math/big"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	"github.com/mvannes/jwt-server/config"
)

func Routes(config config.Config) *chi.Mux {
	h := ProvideKeyHandler()
	r := chi.NewRouter()

	r.Get("/rotate", h.RotateKey)
	r.Get(config.JWKLocationURL, h.GetJWKs)

	return r
}

type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KeyId     string `json:"kid"`
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	Modulus   string `json:"mod"`
	Exponent  string `json:"exp"`
}

func newJWK(keyId string, modulus string, exponent string) JWK {
	return JWK{
		KeyId:     keyId,
		KeyType:   "RSA",
		Algorithm: "RS512",
		Use:       "sig",
		Modulus:   modulus,
		Exponent:  exponent,
	}
}

type KeyHandler struct {
	KeyManager KeyManagerInterface
}

func ProvideKeyHandler() *KeyHandler {
	return &KeyHandler{KeyManager: NewKeyManager()}
}

func (h *KeyHandler) RotateKey(w http.ResponseWriter, r *http.Request) {
	err := h.KeyManager.CreateKeyPair()
	if nil != err {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	render.PlainText(w, r, "key-rotated")
}

func (h *KeyHandler) GetJWKs(w http.ResponseWriter, r *http.Request) {
	keys := make([]JWK, 0)

	keyVersions, err := h.KeyManager.FetchAllKeyVersions()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, keyVersion := range keyVersions {
		keyPair, err := h.KeyManager.FetchKeyPair(keyVersion)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		keys = append(
			keys,
			newJWK(
				keyVersion,
				base64.URLEncoding.EncodeToString(keyPair.PublicKey.N.Bytes()),
				base64.URLEncoding.EncodeToString(new(big.Int).SetInt64(int64(keyPair.PublicKey.E)).Bytes()),
			),
		)
	}

	res := JWKSResponse{
		Keys: keys,
	}

	render.JSON(w, r, res)
}
