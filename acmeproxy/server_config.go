package acmeproxy

import (
	"net/http"

	"github.com/go-acme/lego/challenge"
)

type Config struct {
	HttpServer     *http.Server
	Provider       challenge.Provider
	ProviderName   string
	HtpasswdFile   string
	AllowedIPs     []string
	AllowedDomains []string
	AccesslogFile  string
}

func NewDefaultConfig() *Config {
	return &Config{}
}
