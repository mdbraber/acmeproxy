package cmd

import (
	"crypto/tls"
	golog "log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mdbraber/acmeproxy/acmeproxy"
	aplog "github.com/mdbraber/acmeproxy/log"
	"github.com/mholt/certmagic"
	log "github.com/sirupsen/logrus"
	"github.com/xenolf/lego/certcrypto"
	xlog "github.com/xenolf/lego/log"
	"github.com/xenolf/lego/providers/dns"
	"gopkg.in/urfave/cli.v1"
)

const (
	SSLModeManual string = "manual"
	SSLModeAuto   string = "auto"
)

func getConfig(ctx *cli.Context) *acmeproxy.Config {

	setupLogging(ctx)

	// Read environment variables from the config file
	for _, env := range ctx.GlobalStringSlice("environment") {
		e := strings.Split(env, "=")
		os.Setenv(e[0], e[1])
		log.WithFields(log.Fields{
			"name":  e[0],
			"value": e[1],
		}).Debugf("Using environment variable")
	}

	// Require a DNS provider
	if ctx.GlobalString("provider") == "" {
		log.Fatal("Please specify a provider with --provider/-p")
	}

	// Check if we can get a valid DNS provider (if the right environment variables are set)
	provider, err := dns.NewDNSChallengeProviderByName(ctx.GlobalString("provider"))
	if err != nil {
		log.Fatalf("Unable to setup a valid DNS provider: %s", err.Error())
	}

	// Check SSL settings
	if ctx.GlobalString("ssl") == SSLModeManual && (len(ctx.GlobalString("ssl.manual.cert-file")) == 0 || len(ctx.GlobalString("ssl.manual.key-file")) == 0) {
		log.Fatal("When using --ssl/-s please specify your own certificate/key files with --ssl.manual.cert-file and --ssl.manual.key-file")
	}

	// Set certmagic variables
	if len(ctx.GlobalString("ssl.auto.provider")) == 0 {
		err := ctx.GlobalSet("ssl.auto.provider", ctx.GlobalString("provider"))
		if err != nil {
			log.Fatal("Problem setting ssl.auto.provider")
		}
	}

	// Debug flag names
	for _, flagName := range ctx.GlobalFlagNames() {
		log.WithField(flagName, ctx.GlobalString(flagName)).Debug("Using flag")
	}

	// Setup config
	config := acmeproxy.NewDefaultConfig()
	config.Provider = provider
	config.ProviderName = ctx.GlobalString("provider")
	config.AllowedDomains = ctx.GlobalStringSlice("allowed-domains")
	config.HtpasswdFile = ctx.GlobalString("htpasswd-file")
	config.AccesslogFile = ctx.GlobalString("accesslog-file")

	config.HttpServer = newHttpServer(ctx)
	// FIXME This is sort of weird... (using config in a config)
	// this should be done by newHttpServer:
	config.HttpServer.Handler = acmeproxy.GetHandler(config)

	return config
}

func setupLogging(ctx *cli.Context) {
	// Setup logging
	tf := new(aplog.TextFormatter)

	if ctx.GlobalBool("log-timestamp") {
		tf.FullTimestamp = true
		tf.TimestampFormat = time.Stamp
	} else {
		tf.DisableTimestamp = true
	}

	if ctx.GlobalBool("log-forcecolors") {
		tf.ForceColors = true
	}

	if ctx.GlobalBool("log-forceformatting") {
		tf.ForceFormatting = true
	}

	log.SetFormatter(tf)

	level, err := log.ParseLevel(ctx.GlobalString("log-level"))
	if err != nil {
		log.Fatal(err.Error())
	}
	log.SetLevel(level)

	// Capture regular logging
	logger := log.New()
	logger.SetLevel(level)
	logger.SetFormatter(tf)
	golog.SetFlags(0)
	golog.SetOutput(logger.Writer())
}

func newHttpServer(ctx *cli.Context) *http.Server {

	var server = &http.Server{
		Addr: net.JoinHostPort(ctx.GlobalString("interface"), strconv.Itoa(ctx.GlobalInt("port"))),
		// FIXME error checking!
	}

	switch ctx.GlobalString("ssl") {
	case SSLModeManual:
		log.Info("Setting up server using SSL (manual)")
		tlsConfig := &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			//FIXME: other options?
		}

		tlsCert, err := tls.LoadX509KeyPair(ctx.GlobalString("ssl.manual.cert-file"), ctx.GlobalString("ssl.manual.key-file"))
		if err != nil {
			if os.IsNotExist(err) {
				log.Fatalf("Could not load X509 key pair (cert: %q, key: %q): %v", ctx.GlobalString("ssl.manual.cert-file"), ctx.GlobalString("ssl.manual.key-file"), err)
			}
			log.Fatalf("Error reading X509 key pair (cert: %q, key: %q): %v. Make sure the key is not encrypted.", ctx.GlobalString("ssl.manual.cert-file"), ctx.GlobalString("ssl.manual.key-file"), err)
		}
		tlsConfig.Certificates = []tls.Certificate{tlsCert}
		server.TLSConfig = tlsConfig
	case SSLModeAuto:
		log.Info("Setting up server using SSL (certmagic)")

		salog := log.WithField("prefix", "ssl.auto")
		xlog.Logger = salog

		cmProvider, err := dns.NewDNSChallengeProviderByName(ctx.GlobalString("ssl.auto.provider"))
		if err != nil {
			salog.WithField("error", err.Error()).Fatal("Unable to connect to a valid DNS provider for ssl.auto")
		}

		// FIXME check for errors with FileStorage?
		certmagic.DefaultStorage = &certmagic.FileStorage{Path: ctx.GlobalString("ssl.auto.path")}

		magic := certmagic.New(certmagic.Config{
			CA:                      ctx.GlobalString("ssl.auto.ca"),
			Email:                   getEmail(ctx),
			Agreed:                  ctx.GlobalBool("ssl.auto.agreed"),
			KeyType:                 getKeyType(ctx),
			DNSProvider:             cmProvider,
			DisableHTTPChallenge:    true,
			DisableTLSALPNChallenge: true,
		})

		magicErr := magic.Manage([]string{ctx.GlobalString("interface")})
		if magicErr != nil {
			salog.WithField("error", magicErr.Error()).Fatal("Problem setting up certificates for ssl.auto")
		}
		server.TLSConfig = magic.TLSConfig()
	default:
		log.Info("Setting up server (HTTP)")
	}

	return server

}

// getKeyType the type from which private keys should be generated
func getKeyType(ctx *cli.Context) certcrypto.KeyType {
	keyType := ctx.GlobalString("ssl.auto.key-type")
	switch strings.ToUpper(keyType) {
	case "RSA2048":
		return certcrypto.RSA2048
	case "RSA4096":
		return certcrypto.RSA4096
	case "RSA8192":
		return certcrypto.RSA8192
	case "EC256":
		return certcrypto.EC256
	case "EC384":
		return certcrypto.EC384
	}

	log.Fatalf("Unsupported KeyType: %s", keyType)
	return ""
}

func getEmail(ctx *cli.Context) string {
	email := ctx.GlobalString("ssl.auto.email")
	if len(email) == 0 {
		log.Fatal("You have to pass an account (email address) to the program using --ssl.auto.email")
	}
	return email
}
