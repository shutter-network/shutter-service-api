package common

import "net/url"

type Config struct {
	KeyperHTTPURL *url.URL
}

func NewConfig(keyperHTTPUrl string) (*Config, error) {
	parsedURL, err := url.Parse(keyperHTTPUrl)
	if err != nil {
		return nil, err
	}
	return &Config{
		KeyperHTTPURL: parsedURL,
	}, nil
}
