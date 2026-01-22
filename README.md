# OPNsense module for Caddy

This package contains a DNS provider module for [Caddy](https://github.com/caddyserver/caddy). It is used to manage DNS records in [OPNsense](https://opnsense.org/#) dnsmasq or unbound.
You can combine it with Caddys DNS-01 ACME challange to get valid TLS certs for internal domains.

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/mietzen/caddy-dns-opnsense)

## Caddy module name

```
dns.providers.opnsense
```

## Config examples

To use this module for the internal domain overwrite, together with [mholt/caddy-dynamicdns](https://github.com/mholt/caddy-dynamicdns), with the `dynamic_domains` option like so:

`dns_service` can be `dnsmasq` or `unbound`

```json
{
	"apps": {
		"dynamic_dns": {
			"dns_provider": {
				"name": "opnsense",
				"host": "{env.OPNSENSE_HOST}",
				"api_key": "{env.OPNSENSE_API_KEY}",
				"api_secret_key": "{env.OPNSENSE_API_SECRET_KEY}",
				"dns_service": "dnsmasq",
				"insecure": true,
				"entry_description": "Managed by Caddy"
			},
			"domains": {
				"example.com": ["@"]
			},
			"ip_sources": [
				{
					"source": "interface",
					"name": "eth0"
				}
			],
			"check_interval": "5m",
			"versions": {
				"ipv4": true,
				"ipv6": true
			},
			"ttl": "1h",
			"dynamic_domains": true
		}
	}
}
```

or with the Caddyfile:

```text
# globally
{
	dynamic_dns {
		provider opnsense {
			host {env.OPNSENSE_HOST}
			api_key {env.OPNSENSE_API_KEY}
			api_secret_key {env.OPNSENSE_API_SECRET_KEY}
			dns_service dnsmasq # or unbound
			insecure # Optional: skip TLS verification for self-signed certs
			entry_description Managed by Caddy # Optional
		}
		domains {
			example.com @
		}
		dynamic_domains
		ip_source interface eth0
		check_interval 5m
		ttl 1h
	}
}
```

### Valid local TLS Certs

Here an example using porkbun, but you can use any of the available [caddy-dns](https://github.com/caddy-dns) providers:

```text
{
	dynamic_dns {
		provider opnsense {
			host {env.OPNSENSE_HOST}
			api_key {env.OPNSENSE_API_KEY}
			api_secret_key {env.OPNSENSE_API_SECRET_KEY}
			dns_service dnsmasq # or unbound
			insecure # Optional: skip TLS verification for self-signed certs
		}
		domains {
			example.com @
		}
		dynamic_domains
		ip_source interface eth0
		check_interval 5m
		ttl 1h
	}
	acme_dns porkbun {
		api_key {env.PORKBUN_API_KEY}
		api_secret_key {env.PORKBUN_API_SECRET_KEY}
	}
}
```

### Docker usage

If you want to use this inside a docker container use the `static` `ip_source` module to set the IP of the docker Host

```text
{
	dynamic_dns {
		provider opnsense {
			host {env.OPNSENSE_HOST}
			api_key {env.OPNSENSE_API_KEY}
			api_secret_key {env.OPNSENSE_API_SECRET_KEY}
			dns_service dnsmasq # or unbound
			insecure # Optional: skip TLS verification for self-signed certs
		}
		domains {
			example.com @
		}
		dynamic_domains
		ip_source static {env.DOCKER_HOST_IP}
		check_interval 5m
		ttl 1h
	}
	acme_dns porkbun {
		api_key {env.PORKBUN_API_KEY}
		api_secret_key {env.PORKBUN_API_SECRET_KEY}
	}
}
```
