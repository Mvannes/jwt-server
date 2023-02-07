package user

import (
	"encoding/json"
	"github.com/mvannes/jwt-server/two_factor"
	"github.com/pquerna/otp/totp"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	validator "github.com/go-playground/validator/v10"
	"github.com/mvannes/jwt-server/config"
)

func Routes(config config.Config) *chi.Mux {
	h := ProvideUserHandler(config)
	r := chi.NewRouter()

	r.Get("/users", h.UserList)
	r.Post("/signup", h.SignUpUser)
	r.Post("/users/{username}/two-factor", h.UpdateTwoFactor)

	return r
}

type UserSignUpRequest struct {
	Username string `json:"username" validate:"required,max=256"`
	Name     string `json:"name" validate:"required,max=256"`
	Password string `json:"password" validate:"required"`
}

type UserResponse struct {
	Username string `json:"username"`
	Name     string `json:"name"`
}
type UpdateTwoFactorRequest struct {
	Type two_factor.TwoFactorType `json:"type" validate:"required"`
}
type UserHandler struct {
	UserRepository UserRepository
	Config         config.Config
}

func ProvideUserHandler(config config.Config) *UserHandler {
	return &UserHandler{
		UserRepository: NewJSONUserRepository("users", "people.json"),
		Config:         config,
	}
}

func (h *UserHandler) SignUpUser(w http.ResponseWriter, r *http.Request) {
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

	newUser, err := NewUser(ur.Username, ur.Name, ur.Password)
	if nil != err {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	err = h.UserRepository.StoreUser(newUser)
	if nil != err {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	render.PlainText(w, r, "User added successfully")
}

func (h *UserHandler) UserList(w http.ResponseWriter, r *http.Request) {
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

func (h *UserHandler) UpdateTwoFactor(w http.ResponseWriter, r *http.Request) {
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
	case two_factor.TwoFactorDisabled:
		u.TwoFactorInfo.Type = two_factor.TwoFactorDisabled
		u.TwoFactorInfo.OneTimePasswordSecret = ""
	case two_factor.TwoFactorAuthenticator:
		u.TwoFactorInfo.Type = two_factor.TwoFactorAuthenticator
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
