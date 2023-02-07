package jwt

import (
	"encoding/json"
	"fmt"
	"github.com/mvannes/jwt-server/two_factor"
	"github.com/mvannes/jwt-server/user"
	"github.com/pquerna/otp/totp"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	validator "github.com/go-playground/validator/v10"
	"github.com/mvannes/jwt-server/config"
	"golang.org/x/crypto/bcrypt"
)

func Routes(config config.Config) *chi.Mux {
	h := ProvideJWTHandler(config)
	r := chi.NewRouter()

	r.Post("/login", h.SigninUser)
	r.Post("/login/two-factor/challenge", h.ValidateTwoFactor)
	r.Post("/login/refresh", h.RefreshToken)
	r.Post("/token/invalidate", h.InvalidateToken)

	return r
}

type UserSignInRequest struct {
	Username string `json:"username" validate:"required,max=256"`
	Password string `json:"password" validate:"required"`
}

type UserSignInResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type TwoFactorRequiredResponse struct {
	TwoFactorToken string `json:"twoFactorToken"`
}

type InvalidateTokenRequest struct {
	UUID string `json:"uuid" validate:"required,uuid"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type ValidateTwoFactorRequest struct {
	Code string `json:"code" validate:"required"`
}

type JWTHandler struct {
	UserRepository user.UserRepository
	TokenManager   TokenManagerInterface
	Config         config.Config
}

func ProvideJWTHandler(config config.Config) *JWTHandler {
	return &JWTHandler{
		UserRepository: user.NewJSONUserRepository("users", "people.json"),
		TokenManager:   NewTokenManager(config),
		Config:         config,
	}
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
	u, err := h.UserRepository.GetUser(ur.Username)
	if nil != err {
		if err == user.UserNotFoundError {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(ur.Password)); nil != err {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Return 2fa access token if that is required to log in properly.
	if u.TwoFactorInfo.Type != two_factor.TwoFactorDisabled {
		tt, err := h.TokenManager.CreateTwoFactorToken(u.Username)
		if nil != err {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		render.JSON(w, r, TwoFactorRequiredResponse{TwoFactorToken: tt})
		return
	}

	at, err := h.TokenManager.CreateAccessToken(u.Username, u.Name)
	if nil != err {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rt, err := h.TokenManager.CreateRefreshToken(u.Username)

	if nil != err {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	render.JSON(w, r, UserSignInResponse{
		AccessToken:  at,
		RefreshToken: rt,
	})
}

func (h *JWTHandler) InvalidateToken(w http.ResponseWriter, r *http.Request) {
	var itr InvalidateTokenRequest

	err := json.NewDecoder(r.Body).Decode(&itr)

	if nil != err {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = validator.New().Struct(itr)

	if nil != err {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return // Everything that does a render of the plaintext, should not do that instead.
	}

	err = h.TokenManager.InvalidateRefreshToken(itr.UUID)
	if nil != err {
		if err == errTokenNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	render.PlainText(w, r, "Token invalidated")
}

func (h *JWTHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var rtr RefreshTokenRequest

	err := json.NewDecoder(r.Body).Decode(&rtr)
	if nil != err {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = validator.New().Struct(rtr)
	if nil != err {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rt, err := h.TokenManager.DecodeRefreshToken(rtr.RefreshToken)
	if nil != err {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	u, err := h.UserRepository.GetUser(rt.Username)
	if nil != err {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	at, err := h.TokenManager.CreateAccessToken(u.Username, u.Name)
	if nil != err {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	render.PlainText(w, r, at)
}

func (h *JWTHandler) ValidateTwoFactor(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	// Decode the bearer header here to use that in validating the 2fa request.
	fmt.Println(authHeader)

	var vtfr ValidateTwoFactorRequest
	err := json.NewDecoder(r.Body).Decode(&vtfr)
	if nil != err {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	username := chi.URLParam(r, "username")
	u, err := h.UserRepository.GetUser(username)
	if nil != err {
		if err == user.UserNotFoundError {
			http.Error(w, err.Error(), 404)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if u.TwoFactorInfo.Type == two_factor.TwoFactorDisabled {
		http.Error(w, "Two factor was not enabled for this user", http.StatusBadRequest)
		return
	}

	msg := "invalid code"
	if totp.Validate(vtfr.Code, u.TwoFactorInfo.OneTimePasswordSecret) {
		msg = "valid code!"
	}
	// Everything that does a render of the plaintext, should not do that instead.
	render.PlainText(w, r, msg)
}
