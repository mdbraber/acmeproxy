package acmeproxy

import (
	"net/http"
	"github.com/go-acme/lego/v3/challenge"
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
