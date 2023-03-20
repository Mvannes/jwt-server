package user

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"io/ioutil"
	"os"
	"path"
)

var UserExistsError = errors.New("User already exists")
var UserNotFoundError = errors.New("User not found")

type User struct {
	Id       uuid.UUID `json:"id"`
	Username string    `json:"username"`
	Name     string    `json:"name"`
}

func NewUser(username, name string) User {
	return User{
		Id:       uuid.New(),
		Username: username,
		Name:     name,
	}
}

type UserRepository interface {
	GetUserByID(userID uuid.UUID) (User, error)
	GetUser(username string) (User, error)
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

func (us *JSONUserRepository) GetUserByID(userID uuid.UUID) (User, error) {
	userList, err := us.GetUserList()
	if nil != err {
		return User{}, err
	}

	for _, user := range userList {
		if user.Id == userID {
			return user, nil
		}
	}

	return User{}, UserNotFoundError
}

func (us *JSONUserRepository) GetUser(username string) (User, error) {
	userList, err := us.GetUserList()
	if nil != err {
		return User{}, err
	}

	for _, user := range userList {
		if user.Username == username {
			return user, nil
		}
	}

	return User{}, UserNotFoundError
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

	var userList []User
	if len(fileContent) > 0 {
		if err = json.Unmarshal(fileContent, &userList); nil != err {
			return userList, err
		}
	}

	return userList, nil
}
