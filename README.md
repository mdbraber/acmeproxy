# acme-proxy
Proxy server for ACME DNS challenges written in Go. See the current PR for this provider in lego here: https://github.com/xenolf/lego/pull/708

# Usage

You can specify the following options on the commandline when starting acme-proxy:
- `ACMEPROXY_PROVIDER`: provider to proxy requests for (integrates all lego DNS providers)
- `ACMEPROXY_HOST`: listen on this host for requests (default: 127.0.0.1)
- `ACMEPROXY_PORT`: listen on this port for requests (default: 9095)

You need to also specify the relevant options for the provider you've chosen. See the [lego](github.com/xenolf/lego) documentation. 

If you want to provide proxies for multiple providers, start multiple instances on different hosts/ports.

# Example
You need a version of lego that supports the acme-proxy provider (see my [fork](github.com/mdbraber/lego))

## Running the proxy:
```
mdbraber-mbp:acme-proxy mdbraber$ ACMEPROXY_PROVIDER="transip" TRANSIP_ACCOUNT_NAME="mdbraber" TRANSIP_PRIVATE_KEY_PATH="/Users/mdbraber/transip.key" go run acme-proxy.go
```

## Requesting a certificate:

```
mdbraber-mbp:lego mdbraber$ ACMEPROXY_URL="http://127.0.0.1:9095/" ./lego -m m@mdbraber.com -a -x http-01 -x tls-alpn-01 --dns acme-proxy --dns-resolvers ns0.transip.nl -s https://acme-staging-v02.api.letsencrypt.org/directory -d mdbraber.net -d *.mdbraber.net run
2018/11/08 10:11:38 [INFO] acme: Registering account for m@mdbraber.com
2018/11/08 10:11:38 !!!! HEADS UP !!!!
2018/11/08 10:11:38
		Your account credentials have been saved in your Let's Encrypt
		configuration directory at "/Users/mdbraber/go/src/github.com/mdbraber/lego/.lego/accounts/acme-staging-v02.api.letsencrypt.org/m@mdbraber.com".
		You should make a secure backup	of this folder now. This
		configuration directory will also contain certificates and
		private keys obtained from Let's Encrypt so making regular
		backups of this folder is ideal.
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

