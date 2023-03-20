package user

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"github.com/mvannes/jwt-server/config"
)

func Routes(config config.Config) *chi.Mux {
	h := ProvideUserHandler(config)
	r := chi.NewRouter()

	r.Get("/", h.UserList)

	return r
}

type UserResponse struct {
	Username string `json:"username"`
	Name     string `json:"name"`
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
