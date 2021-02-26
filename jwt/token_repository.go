package jwt

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path"
)

var errTokenNotFound = errors.New("Refresh token was not found")

type RefreshTokenRepository interface {
	GetToken(uuid string) (RefreshToken, error)
	StoreToken(token RefreshToken) error
}

var refreshTokenRepositoryInstance *JSONRefreshTokenRepository

func NewJSONRefreshTokenRepository(storageDir string, fileName string) *JSONRefreshTokenRepository {
	if nil == refreshTokenRepositoryInstance {
		refreshTokenRepositoryInstance = &JSONRefreshTokenRepository{
			storageDir: storageDir,
			fileName:   fileName,
		}
	}
	return refreshTokenRepositoryInstance
}

type JSONRefreshTokenRepository struct {
	storageDir string
	fileName   string
}

type RefreshToken struct {
	UUID      string `json:"uuid"`
	Username  string `json:"username"`
	Valid     bool   `json:"valid"`
	CreatedAt int64  `json:"createdAt"`
}

func (r *JSONRefreshTokenRepository) GetToken(uuid string) (RefreshToken, error) {
	tokenList, err := r.getTokenList()
	if nil != err {
		return RefreshToken{}, err
	}

	for _, token := range tokenList {
		if token.UUID == uuid {
			return token, nil
		}
	}
	return RefreshToken{}, errTokenNotFound
}

func (r *JSONRefreshTokenRepository) StoreToken(token RefreshToken) error {
	basePath := path.Join(r.storageDir)

	_, err := os.Stat(basePath)
	if os.IsNotExist(err) {
		err = os.MkdirAll(basePath, os.ModePerm)
	}

	if nil != err {
		return err
	}

	tokenList, err := r.getTokenList()
	if nil != err {
		return err
	}

	found := false
	for key, storedToken := range tokenList {
		if storedToken.UUID == token.UUID {
			storedToken.Username = token.Username
			storedToken.Valid = token.Valid
			found = true
			tokenList[key] = storedToken
			continue
		}

		if storedToken.Username != token.Username {
			continue
		}
		storedToken.Valid = false
		tokenList[key] = storedToken
	}

	if !found {
		tokenList = append(tokenList, token)
	}

	jsonList, err := json.Marshal(tokenList)
	if nil != err {
		return err
	}

	err = ioutil.WriteFile(path.Join(r.storageDir, r.fileName), jsonList, 0644)
	return err
}

func (r *JSONRefreshTokenRepository) getTokenList() ([]RefreshToken, error) {
	fileContent, err := ioutil.ReadFile(path.Join(r.storageDir, r.fileName))
	if nil != err {
		if !os.IsNotExist(err) {
			return nil, err
		}
	}

	var tokenList []RefreshToken
	if len(fileContent) > 0 {
		if err = json.Unmarshal(fileContent, &tokenList); nil != err {
			return tokenList, err
		}
	}

	return tokenList, nil
}
