package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/mdbraber/acmeproxy/cmd"
	log "github.com/sirupsen/logrus"
	"gopkg.in/urfave/cli.v1"
	"gopkg.in/urfave/cli.v1/altsrc"
)

var (
	version = "dev"
)

func main() {
	cli.HelpFlag = cli.BoolFlag{
		Name:  "help, h",
		Usage: "Show help",
	}

	app := cli.NewApp()
	app.Name = "acmeproxy"
	app.HelpName = "acmeproxy"
	app.Usage = "Proxy server for ACME DNS challenges"
	app.HideHelp = true
	app.Action = cmd.Run

	app.Version = version
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("acmeproxy version %s %s/%s\n", c.App.Version, runtime.GOOS, runtime.GOARCH)
	}

	defaultPath := ""
	cwd, err := os.Getwd()
	if err == nil {
		defaultPath = filepath.Join(cwd, ".acmeproxy")
	}

	flags := cmd.CreateFlags(defaultPath)
	app.Before = altsrc.InitInputSourceWithContext(flags, altsrc.NewYamlSourceFromFlagFunc("config-file"))
	app.Flags = flags

	sort.Sort(cli.FlagsByName(app.Flags))

	runErr := app.Run(os.Args)
	if runErr != nil {
		log.Fatal(runErr)
	}
}
