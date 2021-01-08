package user

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path"
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
	StorageDir string
	FileName   string
}

var jsonStorageInstance *JSONUserRepository

func NewJSONUserRepository(storageDir string, fileName string) *JSONUserRepository {
	if jsonStorageInstance == nil {
		jsonStorageInstance = &JSONUserRepository{StorageDir: storageDir, FileName: fileName}
	}
	return jsonStorageInstance
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

func (us *JSONUserRepository) StoreUser(email string, name string, password string) error {
	if _, err := os.Stat(us.StorageDir); os.IsNotExist(err) {
		err = os.MkdirAll(us.StorageDir, os.ModePerm)
		if nil != err {
			return err
		}
	}

	userList, err := us.getUserList()
	if nil != err {
		return err
	}

	u := User{
		Email:        email,
		Name:         name,
		PasswordHash: password, // Needs hashing of some sort.
	}

	userList = append(userList, u)

	jsonList, err := json.Marshal(userList)
	if nil != err {
		return err
	}

	err = ioutil.WriteFile(path.Join(us.StorageDir, us.FileName), jsonList, 0644)
	return err
}

func (us *JSONUserRepository) getUserList() ([]User, error) {
	fileContent, err := ioutil.ReadFile(path.Join(us.StorageDir, us.FileName))
	if nil != err {
		if !os.IsNotExist(err) {
			return nil, err
		}
	}

	var userList []User
	if len(fileContent) > 0 {
		if err = json.Unmarshal(fileContent, &userList); nil != err {
			return userList, err
		}
	}

	return userList, nil
}
