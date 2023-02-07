package user

import (
	"encoding/json"
	"errors"
	"github.com/mvannes/jwt-server/two_factor"
	"io/ioutil"
	"os"
	"path"

	"golang.org/x/crypto/bcrypt"
)

var UserExistsError = errors.New("User already exists")
var UserNotFoundError = errors.New("User not found")

type TwoFactor struct {
	Type                  two_factor.TwoFactorType `json:"type"`
	OneTimePasswordSecret string                   `json:"oneTimePasswordSecret"`
}

type User struct {
	Username      string    `json:"username"`
	Name          string    `json:"name"`
	PasswordHash  string    `json:"passwordHash"`
	TwoFactorInfo TwoFactor `json:"twoFactorInfo"`
}

func NewUser(username, name, password string) (User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 6)
	return User{
		Username:     username,
		Name:         name,
		PasswordHash: string(hashedPassword),
		TwoFactorInfo: TwoFactor{
			Type:                  two_factor.TwoFactorDisabled,
			OneTimePasswordSecret: "",
		},
	}, err
}

type UserRepository interface {
	GetUser(username string) (*User, error)
	StoreUser(user User) error
	GetUserList() ([]User, error)
}

type JSONUserRepository struct {
	storageDir string
	fileName   string
}

var jsonUserStorageInstance *JSONUserRepository

func NewJSONUserRepository(storageDir string, fileName string) *JSONUserRepository {
	if jsonUserStorageInstance == nil {
		jsonUserStorageInstance = &JSONUserRepository{storageDir: storageDir, fileName: fileName}
	}
	return jsonUserStorageInstance
}

func (us *JSONUserRepository) GetUser(username string) (*User, error) {
	userList, err := us.GetUserList()
	if nil != err {
		return nil, err
	}

	for _, user := range userList {
		if user.Username == username {
			return &user, nil
		}
	}

	return nil, UserNotFoundError
}

func (us *JSONUserRepository) StoreUser(user User) error {
	if _, err := os.Stat(us.storageDir); os.IsNotExist(err) {
		err = os.MkdirAll(us.storageDir, os.ModePerm)
		if nil != err {
			return err
		}
	}

	userList, err := us.GetUserList()
	if nil != err {
		return err
	}

	userList = append(userList, user)

	jsonList, err := json.Marshal(userList)
	if nil != err {
		return err
	}

	err = os.WriteFile(path.Join(us.storageDir, us.fileName), jsonList, 0644)
	return err
}

func (us *JSONUserRepository) GetUserList() ([]User, error) {
	fileContent, err := ioutil.ReadFile(path.Join(us.storageDir, us.fileName))
	if nil != err {
		if !os.IsNotExist(err) {
			return nil, err
		}
	}

	var userList []User // Make sure that this does not return users with their password.
	if len(fileContent) > 0 {
		if err = json.Unmarshal(fileContent, &userList); nil != err {
			return userList, err
		}
	}

	return userList, nil
}
