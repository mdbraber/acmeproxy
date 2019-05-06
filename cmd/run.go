package cmd

import (
	"github.com/mdbraber/acmeproxy/acmeproxy"
	"gopkg.in/urfave/cli.v1"
)

func Run(ctx *cli.Context) {
	config := getConfig(ctx)
	acmeproxy.RunServer(config)
}
