package jwt

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path"

	"golang.org/x/crypto/bcrypt"
)

var UserExistsError = errors.New("User already exists")
var UserNotFoundError = errors.New("User not found")

type User struct {
	Email        string `json:"email"`
	Name         string `json:"name"`
	PasswordHash string `json:"passwordHash"`
}

type UserRepository interface {
	GetUser(email string) (*User, error)
	StoreUser(email string, name string, password string) error
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

func (us *JSONUserRepository) GetUser(email string) (*User, error) {
	userList, err := us.getUserList()
	if nil != err {
		return nil, err
	}

	for _, user := range userList {
		if user.Email == email {
			return &user, nil
		}
	}

	return nil, UserNotFoundError
}

// TODO: Convert to get user object instead of strings. This is not what should be responsible for making the user object.
func (us *JSONUserRepository) StoreUser(email string, name string, password string) error {
	if _, err := os.Stat(us.storageDir); os.IsNotExist(err) {
		err = os.MkdirAll(us.storageDir, os.ModePerm)
		if nil != err {
			return err
		}
	}

	userList, err := us.getUserList()
	if nil != err {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 6)
	if nil != err {
		return err
	}

	u := User{
		Email:        email,
		Name:         name,
		PasswordHash: string(hashedPassword),
	}

	userList = append(userList, u)

	jsonList, err := json.Marshal(userList)
	if nil != err {
		return err
	}

	err = ioutil.WriteFile(path.Join(us.storageDir, us.fileName), jsonList, 0644)
	return err
}

func (us *JSONUserRepository) getUserList() ([]User, error) {
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
