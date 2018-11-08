package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/xenolf/lego/platform/config/env"
	"github.com/xenolf/lego/providers/dns"
)

type Message struct {
	Domain  string `json:"domain"`
	Token   string `json:"token"`
	KeyAuth string `json:"keyAuth"`
}

type Config struct {
	Host     string
	Port     int
	Provider string
}

func NewDefaultConfig() *Config {
	return &Config{
		Host: env.GetOrDefaultString("ACMEPROXY_HOST", "127.0.0.1"),
		Port: env.GetOrDefaultInt("ACMEPROXY_PORT", 9095),
	}
}

func main() {
	values, err := env.Get("ACMEPROXY_PROVIDER")
	if err != nil {
		panic(err)
	}

	config := NewDefaultConfig()
	config.Provider = values["ACMEPROXY_PROVIDER"]

	mux := http.NewServeMux()

	mux.HandleFunc("/present", func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		msg := &Message{}
		err := json.NewDecoder(req.Body).Decode(msg)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		provider, err := dns.NewDNSChallengeProviderByName(config.Provider)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		err = provider.Present(msg.Domain, msg.Token, msg.KeyAuth)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/cleanup", func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		msg := &Message{}
		err := json.NewDecoder(req.Body).Decode(msg)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		provider, err := dns.NewDNSChallengeProviderByName(config.Provider)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		err = provider.CleanUp(msg.Domain, msg.Token, msg.KeyAuth)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	log.Fatal(http.ListenAndServe(net.JoinHostPort(config.Host, strconv.Itoa(config.Port)), mux))
}
