package jwt

import (
	"encoding/json"
	"jwt-server/user"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

func Routes() *chi.Mux {
	h := ProvideJWTHandler()
	r := chi.NewRouter()

	r.Post("/signup", h.SignUpUser)
	r.Post("/signin", h.SigninUser)
	return r
}

type UserSignUpRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Name     string `json:"name" validate:"required,max=256"`
	Password string `json:"password" validate:"required"`
}

type UserSignInRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type JWTHandler struct {
	UserRepository user.UserRepository
	TokenManager   TokenManagerInterface
}

func ProvideJWTHandler() *JWTHandler {
	return &JWTHandler{
		UserRepository: user.NewJSONUserRepository("users", "people.json"),
		TokenManager:   NewTokenManager(),
	}
}

func (h *JWTHandler) SignUpUser(w http.ResponseWriter, r *http.Request) {
	var ur UserSignUpRequest

	err := json.NewDecoder(r.Body).Decode(&ur)

	if nil != err {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = validator.New().Struct(ur)

	if nil != err {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	u, err := h.UserRepository.GetUser(ur.Email)
	if nil != err && err != user.UserNotFoundError {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if nil != u {
		http.Error(w, user.UserExistsError.Error(), http.StatusConflict)
		return
	}

	err = h.UserRepository.StoreUser(ur.Email, ur.Name, ur.Password)
	if nil != err {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	render.PlainText(w, r, "User added successfully")
}

func (h *JWTHandler) SigninUser(w http.ResponseWriter, r *http.Request) {
	var ur UserSignInRequest

	err := json.NewDecoder(r.Body).Decode(&ur)

	if nil != err {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = validator.New().Struct(ur)

	if nil != err {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := h.UserRepository.GetUser(ur.Email)
	if nil != err {
		if err == user.UserNotFoundError {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Actually hash things here.
	if err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(ur.Password)); nil != err {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	t, err := h.TokenManager.CreateAccessToken(u.Email, u.Name)
	if nil != err {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// This should ofcourse actually set a http-only cookie header.
	render.PlainText(w, r, t)
}
