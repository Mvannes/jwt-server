package jwt

import (
	"jwt-server/key"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Claims struct {
	Email      string `json:"email"`
	Name       string `json:"name"`
	KeyVersion string `json:"keyVersion"`
	jwt.StandardClaims
}
type TokenManagerInterface interface {
	CreateAccessToken(email string, name string) (string, error)
}

type TokenManager struct {
	KeyManager key.KeyManagerInterface
}

var tokenManagerInstance *TokenManager

func NewTokenManager() *TokenManager {
	if nil == tokenManagerInstance {
		tokenManagerInstance = &TokenManager{KeyManager: key.ProvideKeyManager()}
	}
	return tokenManagerInstance
}

func (t *TokenManager) CreateAccessToken(email string, name string) (string, error) {
	latestVersion, err := t.KeyManager.FetchLatestKeyVersion()
	if nil != err {
		return "", err
	}

	keyPair, err := t.KeyManager.FetchKeyPair(latestVersion)
	if nil != err {
		return "", err
	}
	now := time.Now()

	claims := &Claims{
		Email:      email,
		Name:       name,
		KeyVersion: latestVersion,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: now.Add(5 * time.Minute).Unix(),
			IssuedAt:  now.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)

	return token.SignedString(keyPair.PrivateKey)
}
