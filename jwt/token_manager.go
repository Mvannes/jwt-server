package jwt

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/mvannes/jwt-server/config"
	"github.com/mvannes/jwt-server/jwk"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

type TwoFactorClaims struct {
	Username      string `json:"username"`
	TwoFactorType string `json:"twoFactorType"`
	jwt.StandardClaims
}

type AccessTokenClaims struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	jwt.StandardClaims
}

type RefreshTokenClaims struct {
	UUID string `json:"uuid"`
	jwt.StandardClaims
}

type TokenManagerInterface interface {
	DecodeRefreshToken(refreshToken string) (RefreshToken, error)
	DecodeTwoFactorToken(twoFactorToken string) (TwoFactorClaims, error)
	CreateTwoFactorToken(userId uuid.UUID, username string) (string, error)
	CreateAccessToken(userId uuid.UUID, username string, name string) (string, error)
	CreateRefreshToken(userId uuid.UUID) (string, error)
	InvalidateRefreshToken(uuid uuid.UUID) error
}

type TokenManager struct {
	keyManager             jwk.KeyManagerInterface
	refreshTokenRepository RefreshTokenRepository
	config                 config.Config
}

var tokenManagerInstance *TokenManager

func NewTokenManager(config config.Config) *TokenManager {
	if nil == tokenManagerInstance {
		tokenManagerInstance = &TokenManager{
			keyManager:             jwk.NewKeyManager(),
			refreshTokenRepository: NewJSONRefreshTokenRepository("tokens", "tokens.json"),
			config:                 config,
		}
	}
	return tokenManagerInstance
}

func (t *TokenManager) DecodeRefreshToken(refreshToken string) (RefreshToken, error) {
	var c RefreshTokenClaims
	token, err := jwt.ParseWithClaims(
		refreshToken,
		&c,
		func(token *jwt.Token) (interface{}, error) {
			alg := token.Header["alg"]
			if nil == alg {
				return nil, errors.New("No algorithm given")
			}
			if false == strings.HasPrefix(fmt.Sprint(alg), "RS512") {
				return nil, errors.New("Wrong algorithm given")
			}
			kid := token.Header["kid"]
			if nil == kid {
				return nil, errors.New("No key id given")
			}
			keyPair, err := t.keyManager.FetchKeyPair(fmt.Sprint(kid))
			if nil != err {
				return nil, err
			}
			return keyPair.PublicKey, nil
		},
	)
	if nil != err {
		return RefreshToken{}, err
	}

	if !token.Valid {
		return RefreshToken{}, errors.New("Invalid token given")
	}

	rtId, err := uuid.Parse(c.UUID)
	if nil != err {
		return RefreshToken{}, err
	}

	rt, err := t.refreshTokenRepository.GetToken(rtId)
	if nil != err {
		return RefreshToken{}, err
	}

	if false == rt.Valid {
		return RefreshToken{}, errors.New("Given refresh token is no longer valid")
	}
	return rt, nil
}

func (t *TokenManager) DecodeTwoFactorToken(twoFactorToken string) (TwoFactorClaims, error) {
	var c TwoFactorClaims
	token, err := jwt.ParseWithClaims(
		twoFactorToken,
		&c,
		func(token *jwt.Token) (interface{}, error) {
			alg := token.Header["alg"]
			if nil == alg {
				return nil, errors.New("No algorithm given")
			}
			if false == strings.HasPrefix(fmt.Sprint(alg), "RS512") {
				return nil, errors.New("Wrong algorithm given")
			}
			kid := token.Header["kid"]
			if nil == kid {
				return nil, errors.New("No key id given")
			}
			keyPair, err := t.keyManager.FetchKeyPair(fmt.Sprint(kid))
			if nil != err {
				return nil, err
			}
			return keyPair.PublicKey, nil
		},
	)
	if nil != err {
		return c, err
	}

	if !token.Valid {
		return c, errors.New("Invalid token given")
	}
	return c, nil
}

func (t *TokenManager) CreateTwoFactorToken(userId uuid.UUID, username string) (string, error) {
	latestVersion, err := t.keyManager.FetchLatestKeyVersion()
	if nil != err {
		return "", err
	}

	keyPair, err := t.keyManager.FetchKeyPair(latestVersion)
	if nil != err {
		return "", err
	}
	now := time.Now()

	claims := &TwoFactorClaims{
		Username:      username,
		TwoFactorType: "basic",
		StandardClaims: jwt.StandardClaims{
			Subject:   userId.String(),
			ExpiresAt: now.Add(5 * time.Minute).Unix(),
			IssuedAt:  now.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	token.Header["kid"] = latestVersion
	token.Header["jku"] = path.Join(t.config.DomainName, "/jwk", t.config.JWKLocationURL)
	return token.SignedString(keyPair.PrivateKey)
}

func (t *TokenManager) CreateAccessToken(userId uuid.UUID, username string, name string) (string, error) {
	latestVersion, err := t.keyManager.FetchLatestKeyVersion()
	if nil != err {
		return "", err
	}

	keyPair, err := t.keyManager.FetchKeyPair(latestVersion)
	if nil != err {
		return "", err
	}
	now := time.Now()

	claims := &AccessTokenClaims{
		Username: username,
		Name:     name,
		StandardClaims: jwt.StandardClaims{
			Subject:   userId.String(),
			ExpiresAt: now.Add(5 * time.Minute).Unix(),
			IssuedAt:  now.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	token.Header["kid"] = latestVersion
	token.Header["jku"] = path.Join(t.config.DomainName, "/jwk", t.config.JWKLocationURL)
	return token.SignedString(keyPair.PrivateKey)
}

func (t *TokenManager) CreateRefreshToken(userId uuid.UUID) (string, error) {
	latestVersion, err := t.keyManager.FetchLatestKeyVersion()
	if nil != err {
		return "", err
	}

	keyPair, err := t.keyManager.FetchKeyPair(latestVersion)
	if nil != err {
		return "", err
	}
	now := time.Now()

	refreshTokenID := uuid.New()
	claims := &RefreshTokenClaims{
		UUID: refreshTokenID.String(),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: now.Add(24 * time.Hour).Unix(),
			IssuedAt:  now.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	token.Header["kid"] = latestVersion
	token.Header["jku"] = t.config.DomainName + t.config.JWKLocationURL
	tokenString, err := token.SignedString(keyPair.PrivateKey)
	if nil != err {
		return "", err
	}
	err = t.refreshTokenRepository.StoreToken(RefreshToken{UUID: refreshTokenID, UserID: userId, Valid: true, CreatedAt: now.Unix()})
	if nil != err {
		return "", err
	}

	return tokenString, nil
}

func (t *TokenManager) InvalidateRefreshToken(uuid uuid.UUID) error {
	token, err := t.refreshTokenRepository.GetToken(uuid)
	if nil != err {
		return err
	}

	token.Valid = false

	return t.refreshTokenRepository.StoreToken(token)
}
