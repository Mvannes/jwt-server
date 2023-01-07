package jwt

import (
	"encoding/json"
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

	r.Get("/users", h.UserList)
	r.Post("/signup", h.SignUpUser)
	r.Post("/signin", h.SigninUser)
	r.Post("/refresh", h.RefreshToken)
	r.Post("/token/invalidate", h.InvalidateToken)
	r.Post("/users/{username}/two-factor", h.UpdateTwoFactor)
	r.Post("/users/{username}/two-factor/check", h.ValidateTwoFactor)

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

type InvalidateTokenRequest struct {
	UUID string `json:"uuid" validate:"required,uuid"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type UserResponse struct {
	Username string `json:"username"`
	Name     string `json:"name"`
}

type UpdateTwoFactorRequest struct {
	Type TwoFactorType `json:"type" validate:"required"`
}

type ValidateTwoFactorRequest struct {
	Code string `json:"code" validate:"required"`
}

type JWTHandler struct {
	UserRepository UserRepository
	TokenManager   TokenManagerInterface
	Config         config.Config
}

func ProvideJWTHandler(config config.Config) *JWTHandler {
	return &JWTHandler{
		UserRepository: NewJSONUserRepository("users", "people.json"),
		TokenManager:   NewTokenManager(config),
		Config:         config,
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
	if nil != err && err != UserNotFoundError {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if nil != u {
		http.Error(w, UserExistsError.Error(), http.StatusConflict)
		return
	}

	err = h.UserRepository.StoreUser(ur.Username, ur.Name, ur.Password)
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
		if err == UserNotFoundError {
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
		return
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

func (h *JWTHandler) UserList(w http.ResponseWriter, r *http.Request) {
	uList, err := h.UserRepository.GetUserList()

	var resp []UserResponse

	for _, user := range uList {
		resp = append(resp, UserResponse{
			Username: user.Username,
			Name:     user.Name,
		})
	}

	if nil != err {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	render.JSON(w, r, resp)
}

func (h *JWTHandler) UpdateTwoFactor(w http.ResponseWriter, r *http.Request) {
	var utfr UpdateTwoFactorRequest
	err := json.NewDecoder(r.Body).Decode(&utfr)
	if nil != err {
		http.Error(w, err.Error(), 500)
	}

	username := chi.URLParam(r, "username")
	u, err := h.UserRepository.GetUser(username)
	if nil != err {
		if err == UserNotFoundError {
			http.Error(w, err.Error(), 404)
			return
		}
		http.Error(w, err.Error(), 500)
		return
	}

	switch utfr.Type {
	case TwoFactorDisabled:
		u.TwoFactorInfo.Type = TwoFactorDisabled
		u.TwoFactorInfo.OneTimePasswordSecret = ""
	case TwoFactorAuthenticator:
		u.TwoFactorInfo.Type = TwoFactorAuthenticator
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      h.Config.DomainName,
			AccountName: u.Username,
		})
		if nil != err {
			http.Error(w, err.Error(), 500)
			return
		}
		u.TwoFactorInfo.OneTimePasswordSecret = key.Secret()
		// TODO: save this user object properly. Requires some rewrite of user code to be better structured.
		// Consider splitting it all off into its own pkg.
		render.JSON(w, r, key.Secret())
	}
}

func (h *JWTHandler) ValidateTwoFactor(w http.ResponseWriter, r *http.Request) {
	var vtfr ValidateTwoFactorRequest
	err := json.NewDecoder(r.Body).Decode(&vtfr)
	if nil != err {
		http.Error(w, err.Error(), 500)
	}

	username := chi.URLParam(r, "username")
	u, err := h.UserRepository.GetUser(username)
	if nil != err {
		if err == UserNotFoundError {
			http.Error(w, err.Error(), 404)
			return
		}
		http.Error(w, err.Error(), 500)
		return
	}
	if u.TwoFactorInfo.Type == TwoFactorDisabled {
		http.Error(w, "Two factor was not enabled for this user", 400)
		return
	}

	msg := "invalid code"
	if totp.Validate(vtfr.Code, u.TwoFactorInfo.OneTimePasswordSecret) {
		msg = "valid code!"
	}
	// Everything that does a render of the plaintext, should not do that instead.
	render.PlainText(w, r, msg)
}
