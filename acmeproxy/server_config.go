package acmeproxy

import (
	"net/http"

	"github.com/xenolf/lego/challenge"
)

type Config struct {
	HttpServer     *http.Server
	Provider       challenge.Provider
	ProviderName   string
	HtpasswdFile   string
	AllowedDomains []string
	AccesslogFile  string
}

func NewDefaultConfig() *Config {
	return &Config{}
}
