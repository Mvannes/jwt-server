package key

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path"

	"github.com/google/uuid"
)

type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

type KeyManagerInterface interface {
	FetchKeyPair(version string) (KeyPair, error)
	FetchLatestKeyVersion() (string, error)
	CreateKeyPair() error
}

type KeyManager struct {
	storageDir string
}

var KeyNotFound = errors.New("Key not found.")

func NewKeyManager() *KeyManager {
	return &KeyManager{
		storageDir: "keys",
	}
}

func (k *KeyManager) FetchKeyPair(version string) (KeyPair, error) {
	versionPath := path.Join(k.storageDir, version)
	if _, err := os.Stat(versionPath); os.IsNotExist(err) {
		return KeyPair{}, KeyNotFound
	}

	privateKeyString, err := ioutil.ReadFile(path.Join(versionPath, "private.pem"))
	if nil != err {
		return KeyPair{}, err
	}

	privateBlock, _ := pem.Decode(privateKeyString)
	privateKey, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	if nil != err {
		return KeyPair{}, err
	}

	publicKeyString, err := ioutil.ReadFile(path.Join(versionPath, "public.pem"))
	if nil != err {
		return KeyPair{}, err
	}

	publicBlock, _ := pem.Decode(publicKeyString)
	publicKey, err := x509.ParsePKCS1PublicKey(publicBlock.Bytes)
	if nil != err {
		return KeyPair{}, err
	}

	return KeyPair{PrivateKey: privateKey, PublicKey: publicKey}, nil
}

func (k *KeyManager) FetchLatestKeyVersion() (string, error) {
	files, err := ioutil.ReadDir(k.storageDir)
	if nil != err {
		return "", err
	}

	var latestDir os.FileInfo
	for _, f := range files {
		if nil == latestDir || latestDir.ModTime().Before(f.ModTime()) {
			latestDir = f
		}
	}
	if nil == latestDir {
		return "", KeyNotFound
	}

	return latestDir.Name(), nil
}

func (k *KeyManager) CreateKeyPair() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if nil != err {
		return err
	}

	uuid := uuid.New()
	basePath := path.Join(k.storageDir, uuid.String())

	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		err = os.MkdirAll(basePath, os.ModePerm)
	}

	if nil != err {
		return err
	}

	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	privatePem, err := os.Create(path.Join(basePath, "private.pem"))
	if nil != err {
		return err
	}

	err = pem.Encode(privatePem, privateKeyBlock)
	if nil != err {
		return err
	}

	publicKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	}

	publicPem, err := os.Create(path.Join(basePath, "public.pem"))
	if nil != err {
		return err
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	return err
}
