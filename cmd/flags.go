package cmd

import (
	"github.com/mholt/certmagic"
	"gopkg.in/urfave/cli.v1"
	"gopkg.in/urfave/cli.v1/altsrc"
)

// CreateFlags creates the flags for the CLI
func CreateFlags(defaultPath string) []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:  "config-file",
			Value: "/etc/acmeproxy/config.yml",
			Usage: "Load configuration from `FILE`",
		},
		altsrc.NewStringFlag(cli.StringFlag{
			Name:  "interface",
			Value: "",
			Usage: "Interface (ip or host) to bind for requests",
		}),
		altsrc.NewIntFlag(cli.IntFlag{
			Name:  "port",
			Value: 9095,
			Usage: "Port to bind for requests",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:  "provider",
			Value: "",
			Usage: "DNS challenge provider - see https://github.com/xenolf/lego for options, also set relevant environment variables!",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:  "htpasswd-file",
			Value: defaultPath + "/htpasswd",
			Usage: "Htpassword file `FILE` for username/password authentication",
		}),
		altsrc.NewStringSliceFlag(cli.StringSliceFlag{
			Name:  "allowed-domains",
			Usage: "Set the allowed domain(s) that certificates can be requested for.",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:  "accesslog-file",
			Value: "",
			Usage: "Location of additional accesslog `FILE`",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:  "log-level",
			Value: "info",
			Usage: "Log `LEVEL` (trace|debug|info|warn|error|fatal|panic)",
		}),
		altsrc.NewBoolFlag(cli.BoolFlag{
			Name:  "log-timestamp",
			Usage: "Output date/time on standard output log",
		}),
		altsrc.NewBoolFlag(cli.BoolFlag{
			Name:  "log-forcecolors",
			Usage: "Force colors on output, even when there is no TTY",
		}),
		altsrc.NewBoolFlag(cli.BoolFlag{
			Name:  "log-forceformatting",
			Usage: "Force formatting on output, even when there is no TTY",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:  "ssl",
			Usage: "Provide a HTTPS connection when listening to interface:port (supported: auto or manual)",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:  "ssl.manual.cert-file",
			Value: "",
			Usage: "Location of certificate `FILE` (when using --ssl/-s)",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:  "ssl.manual.key-file",
			Value: "",
			Usage: "Location of key `FILE` (when using --ssl/-s)",
		}),
		altsrc.NewBoolFlag(cli.BoolFlag{
			Name:  "ssl.auto.agreed",
			Usage: "Read and agree to your CA's legal documents",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:  "ssl.auto.email",
			Value: "",
			Usage: "Provide an e-mail address to be linked to your certificates (defaults to $EMAIL)",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name: "ssl.auto.ca",
			//Value: certmagic.LetsEncryptStagingCA,
			Value: certmagic.LetsEncryptProductionCA,
			Usage: "Certmagic CA endpoint",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:  "ssl.auto.key-type",
			Value: "rsa2048",
			Usage: "Key type to use for private keys. Supported: rsa2048, rsa4096, rsa8192, ec256, ec384.",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:  "ssl.auto.path",
			Value: defaultPath + "/certmagic",
			Usage: "`PATH` to store certmagic information",
		}),
		altsrc.NewStringFlag(cli.StringFlag{
			Name:  "ssl.auto.provider",
			Value: "",
			Usage: "Certmagic DNS provider (defaults to --provider/-p)",
		}),
		altsrc.NewStringSliceFlag(cli.StringSliceFlag{
			Name:   "environment",
			Usage:  "Environment variables to set (to be used from YAML)",
			Hidden: true,
		}),
	}
}
