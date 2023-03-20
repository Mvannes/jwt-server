package credential

import (
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/mvannes/jwt-server/user"
	"golang.org/x/crypto/bcrypt"
	"os"
	"path"
)

type TwoFactorType string

const (
	TwoFactorDisabled      TwoFactorType = "disabled"
	TwoFactorAuthenticator               = "authenticator"
)

type TwoFactor struct {
	Type                  TwoFactorType `json:"type"`
	OneTimePasswordSecret string        `json:"oneTimePasswordSecret"`
}

type UserCredentials struct {
	User         user.User
	PasswordHash string
	TwoFactor    TwoFactor
}

var UserCredentialsNotFoundError = errors.New("user credential not found")

type userCredentialsDatabase struct {
	UserId       uuid.UUID `json:"userId"`
	PasswordHash string    `json:"passwordHash"`
	TwoFactor    TwoFactor `json:"twoFactor"`
}

func NewUserCredentials(user user.User, password string) (UserCredentials, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 6)
	if nil != err {
		return UserCredentials{}, err
	}
	return UserCredentials{
		User:         user,
		PasswordHash: string(hashedPassword),
		TwoFactor: TwoFactor{
			Type:                  TwoFactorDisabled,
			OneTimePasswordSecret: "",
		},
	}, nil
}

type UserCredentialRepository interface {
	StoreCredentials(credentials UserCredentials) error
	GetCredentials(user user.User) (UserCredentials, error)
}

type JSONUserCredentialRepository struct {
	storageDir string
	fileName   string
}

var jsonUserCredentialStorageInstance *JSONUserCredentialRepository

func NewJSONUserRepository(storageDir string, fileName string) *JSONUserCredentialRepository {
	if jsonUserCredentialStorageInstance == nil {
		jsonUserCredentialStorageInstance = &JSONUserCredentialRepository{storageDir: storageDir, fileName: fileName}
	}
	return jsonUserCredentialStorageInstance
}

func (r JSONUserCredentialRepository) getCredentialList() ([]userCredentialsDatabase, error) {
	fileContent, err := os.ReadFile(path.Join(r.storageDir, r.fileName))
	if nil != err {
		if !os.IsNotExist(err) {
			return nil, err
		}
	}

	var credList []userCredentialsDatabase
	if len(fileContent) > 0 {
		if err = json.Unmarshal(fileContent, &credList); nil != err {
			return credList, err
		}
	}

	return credList, nil
}

func (r JSONUserCredentialRepository) StoreCredentials(credentials UserCredentials) error {
	if _, err := os.Stat(r.storageDir); os.IsNotExist(err) {
		err = os.MkdirAll(r.storageDir, os.ModePerm)
		if nil != err {
			return err
		}
	}

	existingCredList, err := r.getCredentialList()
	if nil != err {
		return err
	}
	found := false
	for i, c := range existingCredList {
		if c.UserId == credentials.User.Id {
			c.PasswordHash = credentials.PasswordHash
			c.TwoFactor = credentials.TwoFactor
			found = true
			existingCredList[i] = c
		}
	}
	if !found {
		existingCredList = append(existingCredList, userCredentialsDatabase{
			UserId:       credentials.User.Id,
			PasswordHash: credentials.PasswordHash,
			TwoFactor:    credentials.TwoFactor,
		})
	}

	jsonList, err := json.Marshal(existingCredList)
	if nil != err {
		return err
	}

	err = os.WriteFile(path.Join(r.storageDir, r.fileName), jsonList, 0644)
	return err
}

func (r JSONUserCredentialRepository) GetCredentials(user user.User) (UserCredentials, error) {
	credentialList, err := r.getCredentialList()
	if err != nil {
		return UserCredentials{}, err
	}

	for _, c := range credentialList {
		if c.UserId == user.Id {
			return UserCredentials{User: user, PasswordHash: c.PasswordHash, TwoFactor: c.TwoFactor}, nil
		}
	}

	return UserCredentials{}, UserCredentialsNotFoundError
}
