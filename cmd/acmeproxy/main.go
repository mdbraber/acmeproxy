package main

import (
	"fmt"
	"os"
	"os/user"
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
	app := cli.NewApp()
	app.Name = "acmeproxy"
	app.HelpName = "acmeproxy"
	app.Usage = "Proxy server for ACME DNS challenges"
	app.Action = cmd.Run

	app.CustomAppHelpTemplate = `
NAME:
   {{.Name}}{{if .Usage}} - {{.Usage}}{{end}}

USAGE:
   {{if .UsageText}}{{.UsageText}}{{else}}{{.HelpName}} {{if .VisibleFlags}}[global options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}{{end}}{{if .Version}}{{if not .HideVersion}}

VERSION:
   {{.Version}}{{end}}{{end}}{{if .Description}}

DESCRIPTION:
   {{.Description}}{{end}}{{if len .Authors}}

AUTHOR{{with $length := len .Authors}}{{if ne 1 $length}}S{{end}}{{end}}:
   {{range $index, $author := .Authors}}{{if $index}}
   {{end}}{{$author}}{{end}}{{end}}{{if .VisibleCommands}}

OPTIONS:
   {{range $index, $option := .VisibleFlags}}{{if $index}}
   {{end}}{{$option}}{{end}}{{end}}{{if .Copyright}}

COPYRIGHT:
   {{.Copyright}}{{end}}
`

	app.Version = version
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("acmeproxy version %s %s/%s\n", c.App.Version, runtime.GOOS, runtime.GOARCH)
	}

	defaultPath := ""
	usr, err := user.Current()
	if err == nil {
		defaultPath = filepath.Join(usr.HomeDir, ".acmeproxy")
	} else {
		defaultPath = "/etc/acmeproxy"
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
