package main

import (
	"encoding/json"
	"net/http"
	"log"
	"github.com/xenolf/lego/providers/dns"
	"github.com/xenolf/lego/platform/config/env"
	"io/ioutil"
	"strconv"
)

type Request struct {
	Action string `json:"action"` // present or cleanup
	Domain string `json:"domain"`
	KeyAuth string `json:"keyauth"`
}

type Config struct {
	Host string
	Port int
	Provider string
}

func NewDefaultConfig() *Config {
	return &Config{
		Host: env.GetOrDefaultString("ACMEPROXY_HOST","127.0.0.1"),
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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		req := &Request{}
		bdata, _ := ioutil.ReadAll(r.Body)
		if bdata != nil && len(bdata) > 0 {
			err := json.Unmarshal(bdata, &req)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("500 - Internal Server Error: malformed JSON"))
			} else {
				// execute action
				provider, err := dns.NewDNSChallengeProviderByName(config.Provider)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("500 - Internal Server Error: " + err.Error()))
				} else {
					switch req.Action {
						case "cleanup":
							err := provider.CleanUp(req.Domain, "", req.KeyAuth)
							if err != nil {
								w.WriteHeader(http.StatusInternalServerError)
								w.Write([]byte("500 - Internal Server Error: " + err.Error()))
							}
						case "present":
							err := provider.Present(req.Domain, "", req.KeyAuth)
							if err != nil {
								w.WriteHeader(http.StatusInternalServerError)
								w.Write([]byte("500 - Internal Server Error: " + err.Error()))
							}
						default:
							w.WriteHeader(http.StatusInternalServerError)
							w.Write([]byte("500 - Internal Server Error: no correct action found"))
					}
					w.WriteHeader(http.StatusOK)
				}
			}
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("500 - Internal Server Error: no JSON data found"))
		}
	})

	log.Fatal(http.ListenAndServe(config.Host+":"+strconv.Itoa(config.Port), nil))

}
