package jwt

import (
	"encoding/json"
	"fmt"
	"github.com/mvannes/jwt-server/credential"
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

	r.Post("/signup", h.SignUpUser)
	r.Post("/login", h.SigninUser)

	r.Post("/login/{id}/two-factor/", h.UpdateTwoFactor)
	r.Post("/login/two-factor/challenge", h.ValidateTwoFactor)
	r.Post("/login/refresh", h.RefreshToken)
	r.Post("/token/invalidate", h.InvalidateToken)

	return r
}

type UserSignUpRequest struct {
	Username string `json:"username" validate:"required,max=256"`
	Name     string `json:"name" validate:"required,max=256"`
	Password string `json:"password" validate:"required"`
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

type UpdateTwoFactorRequest struct {
	Type credential.TwoFactorType `json:"type" validate:"required"`
}

type JWTHandler struct {
	UserRepository           user.UserRepository
	UserCredentialRepository credential.UserCredentialRepository
	TokenManager             TokenManagerInterface
	Config                   config.Config
}

func ProvideJWTHandler(config config.Config) *JWTHandler {
	return &JWTHandler{
		UserRepository:           user.NewJSONUserRepository("users", "people.json"),
		UserCredentialRepository: credential.NewJSONUserRepository("credentials", "user.json"),
		TokenManager:             NewTokenManager(config),
		Config:                   config,
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

	u, err := h.UserRepository.GetUser(ur.Username)
	if nil != err && err != user.UserNotFoundError {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if nil != u {
		http.Error(w, user.UserExistsError.Error(), http.StatusConflict)
		return
	}

	newUser := user.NewUser(ur.Username, ur.Name)
	newUserCredentials, err := credential.NewUserCredentials(newUser, ur.Password)
	if nil != err {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// This is not in a transaction, TODO: Figure out transactions in go.
	// Maybe its time to move these to actual databases instead of json.
	err = h.UserRepository.StoreUser(newUser)
	if nil != err {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = h.UserCredentialRepository.StoreCredentials(newUserCredentials)
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
	u, err := h.UserRepository.GetUser(ur.Username)
	if nil != err {
		if err == user.UserNotFoundError {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	creds, err := h.UserCredentialRepository.GetCredentials(*u)
	if nil != err {
		if err == credential.UserCredentialsNotFoundError {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(creds.PasswordHash), []byte(ur.Password)); nil != err {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Return 2fa access token if that is required to log in properly.
	if creds.TwoFactor.Type != credential.TwoFactorDisabled {
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
	// TODO:
	// Decode the bearer header here to use that in validating the 2fa request.
	// Ensure this returns some better handling at some point.
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
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	creds, err := h.UserCredentialRepository.GetCredentials(*u)
	if nil != err {
		if err == credential.UserCredentialsNotFoundError {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if creds.TwoFactor.Type == credential.TwoFactorDisabled {
		http.Error(w, "Two factor was not enabled for this user", http.StatusBadRequest)
		return
	}
	msg := "invalid code"
	if totp.Validate(vtfr.Code, creds.TwoFactor.OneTimePasswordSecret) {
		msg = "valid code!"
	}
	// Everything that does a render of the plaintext, should not do that instead.
	render.PlainText(w, r, msg)
}

func (h *JWTHandler) UpdateTwoFactor(w http.ResponseWriter, r *http.Request) {
	var utfr UpdateTwoFactorRequest
	err := json.NewDecoder(r.Body).Decode(&utfr)
	if nil != err {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	username := chi.URLParam(r, "username")
	u, err := h.UserRepository.GetUser(username)
	if nil != err {
		if err == user.UserNotFoundError {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	creds, err := h.UserCredentialRepository.GetCredentials(*u)
	if nil != err {
		if err == credential.UserCredentialsNotFoundError {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	switch utfr.Type {
	case credential.TwoFactorDisabled:
		creds.TwoFactor.Type = credential.TwoFactorDisabled
		creds.TwoFactor.OneTimePasswordSecret = ""
		err = h.UserCredentialRepository.StoreCredentials(creds)
		if nil != err {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		render.PlainText(w, r, "Disabled 2FA")
	case credential.TwoFactorAuthenticator:
		creds.TwoFactor.Type = credential.TwoFactorAuthenticator
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      h.Config.DomainName,
			AccountName: u.Username,
		})
		if nil != err {
			http.Error(w, err.Error(), 500)
			return
		}
		creds.TwoFactor.OneTimePasswordSecret = key.Secret()
		err = h.UserCredentialRepository.StoreCredentials(creds)
		if nil != err {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		render.JSON(w, r, key.Secret())
	}

}
