This project is not currently being developed and available as reference. There is a [Perl re-implementation](https://github.com/madcamel/acmeproxy.pl/) or you can take a look at the forks.

# acmeproxy
Proxy server for ACME DNS challenges written in Go.

Works with the [httpreq](https://github.com/go-acme/lego/tree/master/providers/dns/httpreq) DNS challenge provider in [lego](https://github.com/go-acme/lego) and with the [acmeproxy](https://github.com/Neilpang/acme.sh/blob/dev/dnsapi/dns_acmeproxy.sh) provider in acme.sh (currently in the dev branch).

## Why?
Acmeproxy was written to provide a way make it easier and safer to automatically issue per-host [Let's Encrypt](https://letsencrypt.org) SSL certificates inside a larger network with many different hosts. Especially when these hosts aren't accessible from the outside, and they need to use the DNS challenges and require DNS API access.

The regular approach would be to run an ACME client on every host, which would also mean giving each hosts access to the (full) DNS API. This is both hard to manage and a potential security risk.

As a solution Acmeproxy provides the following:
- Allow internal hosts to request ACME DNS challenges through a single host, without individual / full API access to the DNS provider
- Provide a single (acmeproxy) host that has access to the DNS credentials / API, limiting a possible attack surface
- Username/password or IP-based filtering for clients to prevent unauthorized access
- Domain validation to only allow ACME DNS requests for specific domains
- Use [certmagic](https://github.com/mholt/certmagic) internally to run a https instance of acmeproxy and manage certificates (set `--ssl auto`)

If you're looking for other ways to validate internal certificates, take a look at [autocertdelegate](https://github.com/bradfitz/autocertdelegate) which uses the tls-alpn-01 method.

Acmeproxy was written to be run within an internal network, it's not recommended to expose your Acmeproxy host to the outside world. Do so at your own risk. 


## Background
See the discussions for this idea in lego [here](https://github.com/go-acme/lego/pull/708)

# Build

## Prerequisite / WARNING

to use acmeproxy as backend with providers from the `lego` package they need to implement a `CreateRecord`/`RemoveRecord` method that takes an FQDN + acme value as input. The discussion if this should be practice is on-going, see [issue 720](https://github.com/go-acme/lego/issues/720). As an example take a look at [PR #883](https://github.com/go-acme/lego/pull/883) of how this was implemented for the `transip` provider (don't worry, it's not difficult).

Use the makefile to `make` the executables. Use `make install` to also install the executable to `/usr/local/bin`.

If you want to build a Debian package / installer, use `dch` to update the changelog and create your own package using `make debian`.

# Configure

## Adjust configuration file
Copy `config.yml` to a directory (default: `/etc/acmeproxy`). See below for a configuration example using the `transip` provider. You need to specify the relevant environment variables for the provider you've chose. See the [lego](https://github.com/go-acme/lego) documentation for options per provider. Also see the examples below. If you want to provide proxies for multiple providers, start multiple instances on different hosts/ports (using different config files).

```
# Environment variables to be used with this provider
environment:
 - "TRANSIP_ACCOUNT_NAME=example"
 - "TRANSIP_PRIVATE_KEY_PATH=/etc/acmeproxy/transip.key"
 - "TRANSIP_POLLING_INTERVAL=30"
 - "TRANSIP_PROPAGATION_TIMEOUT=600"

# General settings
interface: "acmeproxy.example.com"
port: 9096
provider: "transip"
htpasswd-file: "/etc/acmeproxy/htpasswd"
accesslog-file: "/var/log/acmeproxy.log"
log-forcecolors: true
log-forceformatting: true
log-level: debug
log-timestamp: true
allowed-domains:
 - "example.com"
 - "example.net"
 - "anotherexample.net"
allowed-ips:
 - 127.0.0.1
 - 172.0.0/16

# Settings for the acmeproxy SSL certificate (used with this interface)
ssl: manual
ssl.manual.cert-file: "/etc/lego/certificates/acmeproxy.example.com.crt"
ssl.manual.key-file: "/etc/lego/certificates/acmeproxy.example.com.key"
ssl.auto.agreed: true
#ssl.auto.ca: "https://acme-v02.api.letsencrypt.org/directory"
ssl.auto.ca: "https://acme-staging-v02.api.letsencrypt.org/directory"
ssl.auto.email: "johndoe@example.com"
ssl.auto.key-type: "rsa2048"
ssl.auto.path: "/etc/acmeproxy/certmagic"
ssl.auto.provider: "transip"
```

## Authentication 
If you want to use client authentication (username/password), use following command: `htpasswd -c /etc/acmeproxy/htpasswd testuser` to create a new htpasswd file with user `testuser`.

If you want to use serverside IP based authentication set `allowed-ips` in the configfile (or set `--allowed-ips` on the commandline). You can use multiple IPs / nets in a CIDR notation, e.g. `127.0.0.1`, `172.16.0.0/16` or `192.168.10.0/24`.

# Usage

## Running acmeproxy in the foreground
If you've configured acmeproxy via the config file, you can just run `acmeproxy`. It will run in the foreground.

## Daemon mode
If you want to use acmeproxy as a daemon (in the background) use the `acmeproxy.service` in `debian/` as an example for systemd and copy it to `/etc/systemd/systemd` and enable it by `systemctl enable acmeproxy.service`. Be sure to check the `ExecStart` variable to see if it points to the right executable (`/usr/bin/acmeproxy` by default). Of course if you build `acmeproxy` as a Debian package the systemd service will be installed as part of the package.

## Options

```
NAME:
   acmeproxy - Proxy server for ACME DNS challenges

USAGE:
   acmeproxy [global options] [arguments...]

VERSION:
   dev

GLOBAL OPTIONS:
   --accesslog-file FILE        Location of additional accesslog FILE
   --allowed-domains value      Set the allowed domain(s) that certificates can be requested for.
   --allowed-ips value          Set the allowed IP(s) that can request certificates (CIDR notation possible, see https://github.com/jpillora/ipfilter)
   --config-file FILE           Load configuration from FILE (default: "/etc/acmeproxy/config.yml")
   --htpasswd-file FILE         Htpassword file FILE for username/password authentication (default: "/root/.acmeproxy/htpasswd")
   --interface value            Interface (ip or host) to bind for requests
   --log-level LEVEL            Log LEVEL (trace|debug|info|warn|error|fatal|panic) (default: "info")
   --log-forcecolors            Force colors on output, even when there is no TTY
   --log-forceformatting        Force formatting on output, even when there is no TTY
   --log-timestamp              Output date/time on standard output log
   --port value                 Port to bind for requests (default: 9095)
   --provider value             DNS challenge provider - see https://github.com/go-acme/lego for options, also set relevant environment variables!
   --ssl value                  Provide a HTTPS connection when listening to interface:port (supported: auto or manual)
   --ssl.auto.agreed            Read and agree to your CA's legal documents
   --ssl.auto.ca value          Certmagic CA endpoint (default: "https://acme-v02.api.letsencrypt.org/directory")
   --ssl.auto.email value       Provide an e-mail address to be linked to your certificates (defaults to $EMAIL)
   --ssl.auto.key-type value    Key type to use for private keys. Supported: rsa2048, rsa4096, rsa8192, ec256, ec384. (default: "rsa2048")
   --ssl.auto.path PATH         PATH to store certmagic information (default: "/root/.acmeproxy/certmagic")
   --ssl.auto.provider value    Certmagic DNS provider (defaults to --provider/-p)
   --ssl.manual.cert-file FILE  Location of certificate FILE (when using --ssl/-s)
   --ssl.manual.key-file FILE   Location of key FILE (when using --ssl/-s)
   --help, -h                   show help
   --version, -v                print the version
```

## Showing systemd logs

If you run acmeproxy through systemd and use `log-forcecolors: true` and `log-forceformatting: true` - you can use `journalctl -xe -o cat -u acmeproxy.service` to see the original colored output with timestamps
