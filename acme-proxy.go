package main

import (
	"encoding/json"
	"net/http"
	"log"
	"github.com/xenolf/lego/providers/dns"
	"io/ioutil"
)


type Request struct {
	Provider string `json:"provider"`
	Action string `json:"action"` // present or cleanup
	Domain string `json:"domain"`
	KeyAuth string `json:"keyauth"`
}

func main() {

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
				provider, err := dns.NewDNSChallengeProviderByName(req.Provider)
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

	log.Fatal(http.ListenAndServe("127.0.0.1:9095", nil))

}
