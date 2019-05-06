package acmeproxy

import (
	"encoding/json"
	golog "log"
	"net/http"
	"os"
	"strings"
	"time"

	auth "github.com/abbot/go-http-auth"
	log "github.com/sirupsen/logrus"
	"github.com/xenolf/lego/challenge"
	"github.com/xenolf/lego/challenge/dns01"
	"golang.org/x/net/context"
)

const (
	ModeDefault   string = "default"
	ModeRaw       string = "raw"
	ActionPresent string = "present"
	ActionCleanup string = "cleanup"
)

type providerSolved interface {
	challenge.Provider
	CreateRecord(fqdn, value string) error
	RemoveRecord(fqdn, value string) error
}

// message represents the JSON payload
// See https://github.com/xenolf/lego/tree/master/providers/dns/httpreq
type messageDefault struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
}

// message represents the JSON payload
// See https://github.com/xenolf/lego/tree/master/providers/dns/httpreq
type messageRaw struct {
	Domain  string `json:"domain"`
	Token   string `json:"token"`
	KeyAuth string `json:"keyauth"`
}

// Incomingmessage represents the JSON payload of an incoming request
// Should be either FQDN,Value or Domain,Token,KeyAuth
// See https://github.com/xenolf/lego/tree/master/providers/dns/httpreq
type messageIncoming struct {
	messageDefault
	messageRaw
}

type statusWriter struct {
	http.ResponseWriter
	status int
	length int
}

// AuthenticatorInterface is the interface implemented by BasicAuth
// FIXME: is this deprecated?
type AuthenticatorInterface interface {
	// NewContext returns a new context carrying authentication
	// information extracted from the request.
	NewContext(ctx context.Context, r *http.Request) context.Context
}

func GetHandler(config *Config) http.Handler {
	authenticator := &auth.BasicAuth{
		Realm:   "Basic Realm",
		Secrets: auth.HtpasswdFileProvider(config.HtpasswdFile),
	}

	// Define routes
	mux := http.NewServeMux()
	mux.Handle("/present", AuthenticationHandler(authenticator, (ActionHandler(ActionPresent, config))))
	mux.Handle("/cleanup", AuthenticationHandler(authenticator, (ActionHandler(ActionCleanup, config))))

	// Check if we need to write an access log
	var handler http.Handler
	if len(config.AccesslogFile) > 0 {
		accessLogHandle, err := os.OpenFile(config.AccesslogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			panic(err)
		}
		defer accessLogHandle.Close()
		handler = writeAccessLog(mux, accessLogHandle)
	} else {
		handler = mux
	}

	return handler
}

func ActionHandler(action string, config *Config) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		alog := log.WithFields(log.Fields{
			"prefix": action + ": " + r.RemoteAddr,
		})

		// Check authentication
		authInfo := auth.FromContext(r.Context())
		authInfo.UpdateHeaders(w.Header())
		if authInfo == nil || !authInfo.Authenticated {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			alog.Error("Unauthorized request")
			return
		}
		alog.WithField("username", authInfo.Username).Info("Authorized")

		// Check if we're using POST
		if r.Method != http.MethodPost {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			alog.WithField("method", r.Method).Error("Method not allowed")
			return
		}

		// Decode the JSON message
		incoming := &messageIncoming{}
		err := json.NewDecoder(r.Body).Decode(incoming)
		if err != nil {
			http.Error(w, "Bad JSON request", http.StatusBadRequest)
			alog.WithField("error", err.Error()).Error("Method not allowed")
			return
		}

		// Make sure domain and FQDN from the incoming message are correct
		incoming.FQDN = dns01.ToFqdn(incoming.FQDN)
		incoming.Domain = dns01.UnFqdn(incoming.Domain)

		// Check if we've received a message or messageRaw JSON
		// See https://github.com/xenolf/lego/tree/master/providers/dns/httpreq
		var mode string
		var checkDomain string
		if incoming.FQDN != "" && incoming.Value != "" {
			mode = ModeDefault
			checkDomain = dns01.UnFqdn(strings.TrimPrefix(incoming.FQDN, "_acme-challenge."))
			alog.WithFields(log.Fields{
				"fqdn":  incoming.FQDN,
				"value": incoming.Value,
			}).Debug("Received JSON payload")
		} else if incoming.Domain != "" && (incoming.Token != "" || incoming.KeyAuth != "") {
			mode = ModeRaw
			checkDomain = incoming.Domain
			alog.WithFields(log.Fields{
				"domain":  incoming.Domain,
				"token":   incoming.Token,
				"keyAuth": incoming.KeyAuth,
			}).Debug("Received JSON payload")
		} else {
			http.Error(w, "Wrong JSON content", http.StatusBadRequest)
			alog.WithField("json", incoming).Error("Wrong JSON content")
			return
		}

		// Check if we are allowed to requests certificates for this domain
		var allowed = false
		for _, allowedDomain := range config.AllowedDomains {
			alog.WithFields(log.Fields{
				"checkDomain":   checkDomain,
				"allowedDomain": allowedDomain,
			}).Debug("Checking allowed domain")
			if checkDomain == allowedDomain || strings.HasSuffix(strings.SplitAfterN(checkDomain, ".", 2)[1], allowedDomain) {
				allowed = true
				break
			}
		}

		if !allowed {
			http.Error(w, "Requested domain not in allowed-domains", http.StatusInternalServerError)
			alog.WithFields(log.Fields{
				"domain":          checkDomain,
				"allowed-domains": config.AllowedDomains,
			}).Debug("Requested domain not in allowed-domains")
			return
		}

		// Check if this provider supports the selected mode
		// We assume that all providers support MODE_RAW (which is lego default)
		if mode == ModeDefault {
			provider, ok := config.Provider.(providerSolved)
			if ok {
				alog.WithFields(log.Fields{
					"provider": config.ProviderName,
					"mode":     mode,
				}).Debug("Provider supports requested mode")
				err = provider.CreateRecord(incoming.FQDN, incoming.Value)
				if err != nil {
					alog.WithFields(log.Fields{
						"provider": config.ProviderName,
						"fqdn":     incoming.FQDN,
						"value":    incoming.Value,
						"mode":     mode,
						"error":    err.Error(),
					}).Error("Failed to update TXT record")
					http.Error(w, "Failed to update TXT record", http.StatusInternalServerError)
					return
				}
			} else {
				http.Error(w, "Provider does not support requested mode", http.StatusInternalServerError)
				alog.WithFields(log.Fields{
					"provider": config.ProviderName,
					"mode":     mode,
				}).Debug("Provider does not support requested mode")
				return
			}

			// Send back the original JSON to confirm success
			m := messageDefault{FQDN: incoming.FQDN, Value: incoming.Value}
			w.Header().Set("Content-Type", "application/json")
			returnErr := json.NewEncoder(w).Encode(m)
			if returnErr != nil {
				log.Error("Problem encoding return message")
			}

			// Succes!
			alog.WithFields(log.Fields{
				"provider": config.ProviderName,
				"fqdn":     incoming.FQDN,
				"value":    incoming.Value,
				"mode":     mode,
			}).Info("Sucessfully updated TXT record")
			// All lego providers should support raw mode
		} else if mode == ModeRaw {
			fqdn, value := dns01.GetRecord(incoming.Domain, incoming.KeyAuth)
			alog.WithFields(log.Fields{
				"provider": config.ProviderName,
				"mode":     mode,
			}).Debug("Provider supports requested mode")
			provider := config.Provider
			err = provider.Present(incoming.Domain, incoming.Token, incoming.KeyAuth)
			if err != nil {
				alog.WithFields(log.Fields{
					"provider": config.ProviderName,
					"domain":   incoming.Domain,
					"fqdn":     fqdn,
					"token":    incoming.Token,
					"keyAuth":  incoming.KeyAuth,
					"value":    value,
					"mode":     mode,
				}).Error("Failed to update TXT record")
				http.Error(w, "Failed to update TXT record", http.StatusInternalServerError)
				return
			}
			// Send back the original JSON to confirm success
			m := messageRaw{Domain: incoming.Domain, Token: incoming.Token, KeyAuth: incoming.KeyAuth}
			w.Header().Set("Content-Type", "application/json")
			returnErr := json.NewEncoder(w).Encode(m)
			if returnErr != nil {
				log.Error("Problem encoding return message")
			}

			// Succes!
			alog.WithFields(log.Fields{
				"provider": config.ProviderName,
				"domain":   incoming.Domain,
				"fqdn":     fqdn,
				"token":    incoming.Token,
				"keyAuth":  incoming.KeyAuth,
				"value":    value,
				"mode":     mode,
			}).Info("Sucessfully updated TXT record")
		} else {
			http.Error(w, "Unkown mode requested", http.StatusInternalServerError)
			alog.WithFields(log.Fields{
				"provider": config.ProviderName,
				"mode":     mode,
			}).Info("Unknown mode requested")
			return
		}

	})

}

func AuthenticationHandler(a AuthenticatorInterface, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := a.NewContext(r.Context(), r)
		r = r.WithContext(ctx)
		h.ServeHTTP(w, r)
	})
}

// writeAccessLog Logs the Http Status for a request into fileHandler and returns a httphandler function which is a wrapper to log the requests.
func writeAccessLog(handle http.Handler, accessLogHandle *os.File) http.HandlerFunc {
	logger := golog.New(accessLogHandle, "", 0)
	return func(w http.ResponseWriter, request *http.Request) {
		writer := statusWriter{w, 0, 0}
		handle.ServeHTTP(&writer, request)
		end := time.Now()
		statusCode := writer.status
		length := writer.length
		if request.URL.RawQuery != "" {
			logger.Printf("%v %s %s \"%s %s%s%s %s\" %d %d \"%s\"", end.Format("2006/01/02 15:04:05"), request.Host, request.RemoteAddr, request.Method, request.URL.Path, "?", request.URL.RawQuery, request.Proto, statusCode, length, request.Header.Get("User-Agent"))
		} else {
			logger.Printf("%v %s %s \"%s %s %s\" %d %d \"%s\"", end.Format("2006/01/02 15:04:05"), request.Host, request.RemoteAddr, request.Method, request.URL.Path, request.Proto, statusCode, length, request.Header.Get("User-Agent"))
		}
	}
}
