package common

import (
	"crypto/ecdsa"
	"fmt"
	"net/url"
)

type Config struct {
	KeyperHTTPURL *url.URL
	SigningKey    *ecdsa.PrivateKey
	PublicKey     *ecdsa.PublicKey
}

func NewConfig(keyperHTTPUrl string, signingKey *ecdsa.PrivateKey) (*Config, error) {
	parsedURL, err := url.Parse(keyperHTTPUrl)
	if err != nil {
		return nil, err
	}
	publicKey, ok := signingKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cannot create public key")
	}
	return &Config{
		KeyperHTTPURL: parsedURL,
		SigningKey:    signingKey,
		PublicKey:     publicKey,
	}, nil
}
