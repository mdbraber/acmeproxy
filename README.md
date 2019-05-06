# acmeproxy
Proxy server for ACME DNS challenges written in Go. Works with the [httpreq](https://github.com/xenolf/lego/tree/master/providers/dns/httpreq) DNS challenge provider in [lego](https://github.com/xenolf/lego).

## Why?
Acmeproxy was written to provide a way make it easier and safer to automatically issue per-host [Let's Encrypt](https://letsencrypt.org) SSL certificates inside a larger network with many different hosts. Especially when these hosts aren't accessible from the outside, so need to use the DNS challenges and therefore DNS API access. The regular approach would be to run an ACME client on every host, which would also mean giving each hosts access to the (full) DNS API. This is both hard to manage and a potential security risk.

As a solution Acmeproxy provides the following:
- Allow internal hosts to request ACME DNS challenges through a single host, without access to the DNS provider
- Provide a single (acmeproxy) host that has access to the DNS credentials / API, limiting a possible attack surface
- Use username/password for clients to prevent unauthorized access

Acmeproxy was written to be run within an internal network, it's not recommended to expose your Acmeproxy host to the outside world. Do so at your own risk.

## Background
See the discussions for this idea in lego [here](https://github.com/xenolf/lego/pull/708)

# Usage

## Creating username/password file
Use the following command: `htpasswd -c /etc/acmeproxy/htpasswd testuser` to create a new htpasswd file with user `testuser`.

## Using acmeproxy 
You can use the following environment variables on the commandline when starting acme-proxy:




You need to also specify the relevant options for the provider you've chosen with `ACMEPROXY_PROVIDER`. See the [lego](https://github.com/xenolf/lego) documentation for options per provider. Also see the examples below. If you want to provide proxies for multiple providers, start multiple instances on different hosts/ports.


## Optional flags
Acmeproxy only has a single command line flag:
- `-nodatetime`: Omit date/time from logging (e.g. for use with systemd where stdout output is sent to syslog)

# Examples
You need a version of lego that supports the acme-proxy provider (see my [fork](https://github.com/mdbraber/lego))

## Running the proxy:
```
mdbraber-mbp:acme-proxy mdbraber$ ACMEPROXY_PROVIDER="transip" TRANSIP_ACCOUNT_NAME="mdbraber" TRANSIP_PRIVATE_KEY_PATH="/Users/mdbraber/transip.key" go run acme-proxy.go
```

## Requesting a certificate
The example below is using [lego](https://github.com/xenolf/lego) to request a certificate using the [httpreq](https://github.com/xenolf/lego/tree/master/providers/dns/httpreq) plugin (built to connect with a specific API endpoint like acmeproxy. 

```
mdbraber-mbp:lego mdbraber$ HTTPREQ_USERNAME="test" HTTPREQ_PASSWORD="test" HTTPREQ_ENDPOINT="http://acmeproxy.mdbraber.net:9095/" HTTPREQ_PROPAGATION_TIMEOUT=600 ./lego -m m@mdbraber.com -a -x http-01 -x tls-alpn-01 --dns httpreq --dns-resolvers ns0.transip.nl -s https://acme-staging-v02.api.letsencrypt.org/directory -d mdbraber.net -d *.mdbraber.net run
2018/11/08 10:11:38 [INFO] [mdbraber.net, *.mdbraber.net] acme: Obtaining bundled SAN certificate
2018/11/08 10:11:39 [INFO] [*.mdbraber.net] AuthURL: https://acme-staging-v02.api.letsencrypt.org/acme/authz/lBFxlzA3lbOJ8a7cAmIv-vP-Qe1OU4ZSR_q4tmD5Af4
2018/11/08 10:11:39 [INFO] [mdbraber.net] AuthURL: https://acme-staging-v02.api.letsencrypt.org/acme/authz/RY19RDOYqi2UbTBqmU5FmU1ZVx5FT7kP1xsO5dkodIc
2018/11/08 10:11:39 [INFO] [mdbraber.net] acme: Could not find solver for: tls-alpn-01
2018/11/08 10:11:39 [INFO] [mdbraber.net] acme: Could not find solver for: http-01
2018/11/08 10:11:39 [INFO] [mdbraber.net] acme: Preparing to solve DNS-01
2018/11/08 10:11:41 [INFO] [mdbraber.net] acme: Preparing to solve DNS-01
2018/11/08 10:11:43 [INFO] [mdbraber.net] acme: Trying to solve DNS-01
2018/11/08 10:11:43 [INFO] [mdbraber.net] Checking DNS record propagation using [ns0.transip.nl:53]
2018/11/08 10:11:43 [INFO] Wait [timeout: 10m0s, interval: 10s]
2018/11/08 10:14:34 [INFO] [mdbraber.net] The server validated our request
2018/11/08 10:14:34 [INFO] [mdbraber.net] acme: Trying to solve DNS-01
2018/11/08 10:14:34 [INFO] [mdbraber.net] Checking DNS record propagation using [ns0.transip.nl:53]
2018/11/08 10:14:34 [INFO] Wait [timeout: 10m0s, interval: 10s]
2018/11/08 10:14:40 [INFO] [mdbraber.net] The server validated our request
2018/11/08 10:14:42 [INFO] [mdbraber.net, *.mdbraber.net] acme: Validations succeeded; requesting certificates
2018/11/08 10:14:44 [INFO] [mdbraber.net] Server responded with a certificate.
```

