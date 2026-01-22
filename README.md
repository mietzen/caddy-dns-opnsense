# OPNsense DNS module for Caddy

This package contains a DNS provider module for [Caddy](https://github.com/caddyserver/caddy). It is used to manage DNS records in [OPNsense](https://opnsense.org/#) dnsmasq or unbound.
You can combine it with Caddys DNS-01 ACME challenge to get valid TLS certs for internal domains.

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/mietzen/caddy-dns-opnsense)

## Caddy module name

```
dns.providers.opnsense
```

## Config examples

To use this module for the internal domain overwrite, together with [mholt/caddy-dynamicdns](https://github.com/mholt/caddy-dynamicdns), with the `dynamic_domains` option like so:

`dns_service` can be [`dnsmasq`](https://github.com/mietzen/libdns-opnsense-dnsmasq) or [`unbound`](https://github.com/mietzen/libdns-opnsense-unbound)

```json
{
	"apps": {
		"dynamic_dns": {
			"dns_provider": {
				"name": "opnsense",
				"host": "{env.OPNSENSE_HOSTNAME}",
				"api_key": "{env.OPNSENSE_API_KEY}",
				"api_secret_key": "{env.OPNSENSE_API_SECRET}",
				"dns_service": "dnsmasq",
				"insecure": true,
				"entry_description": "Managed by Caddy"
			},
			"domains": {
				"example.com": [""]
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
			host {env.OPNSENSE_HOSTNAME}
			api_key {env.OPNSENSE_API_KEY}
			api_secret_key {env.OPNSENSE_API_SECRET}
			dns_service dnsmasq # or unbound
			insecure # Optional: skip TLS verification for self-signed certs
			entry_description Managed by Caddy # Optional
		}
		domains {
			example.com
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
			host {env.OPNSENSE_HOSTNAME}
			api_key {env.OPNSENSE_API_KEY}
			api_secret_key {env.OPNSENSE_API_SECRET}
			dns_service dnsmasq # or unbound
			insecure # Optional: skip TLS verification for self-signed certs
		}
		domains {
			example.com
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
test_caddy.example.com {
	respond "Welcome to caddy!"
}
```

### Docker usage

If you want to use this inside a docker container use the `static` `ip_source` module to set the IP of the docker Host

```text
{
	dynamic_dns {
		provider opnsense {
			host {env.OPNSENSE_HOSTNAME}
			api_key {env.OPNSENSE_API_KEY}
			api_secret_key {env.OPNSENSE_API_SECRET}
			dns_service dnsmasq # or unbound
			insecure # Optional: skip TLS verification for self-signed certs
		}
		domains {
			example.com
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
test_caddy.example.com {
	respond "Welcome to caddy!"
}
```

#### Docker service discovery

You can also combine this with [caddy-docker-proxy](https://github.com/lucaslorentz/caddy-docker-proxy). Use the Caddyfile from above and add lables to you docker containers:

```yml
    labels:
        caddy: mycontainer.example.com
        caddy.reverse_proxy: "{{upstreams 8080}}"
```

You will automatically get local DNS entries in OPNsense.

## Building with `xcaddy`

Use [`xcaddy`](https://caddyserver.com/docs/build#xcaddy) to build the module:

```
xcaddy build \
    --with github.com/mietzen/caddy-dns-opnsense \
    --with github.com/mietzen/libdns-opnsense-dnsmasq \
    --with github.com/mietzen/libdns-opnsense-unbound \
    --with github.com/mholt/caddy-dynamicdns
```

You don't have to buildin both providers you can just use the one you use, e.g. `dnsmasq`:

```
xcaddy build \
    --with github.com/mietzen/caddy-dns-opnsense \
    --with github.com/mietzen/libdns-opnsense-dnsmasq \
    --with github.com/mholt/caddy-dynamicdns
```

You also will most likely add your DNS Provider for ACME, here `porkbun`:

```
xcaddy build \
    --with github.com/mietzen/caddy-dns-opnsense \
    --with github.com/mietzen/libdns-opnsense-dnsmasq \
    --with github.com/mholt/caddy-dynamicdns \
    --with github.com/caddy-dns/porkbun
```

## Setting up OPNsense API keys

1. Create a new API-User under **System** -> **Access** -> **Users**
	- Set `Scrambled Password` to `True` and make sure `Login shell` is `None`
 	    
  	  <img width="600" height="1184" alt="image" src="https://github.com/user-attachments/assets/7d574600-5f8b-401e-89a8-3fa5c67e18b5" />
  	- Set the Permissions for Dnsmasq to: `Services: Dnsmasq DNS/DHCP: Settings`
   	    
   	  <img width="600" height="906" alt="image" src="https://github.com/user-attachments/assets/902d0c5e-d6fa-4254-ad56-2bc4e76b3582" />
  	- Set the Permissions for Unbound to: `Services: Unbound (MVC)` & `Services: Unbound DNS: Edit Host and Domain Override`
   	    
	  <img width="600" height="906" alt="image" src="https://github.com/user-attachments/assets/a24c95e2-c857-4edb-9c21-d54417ed7799" />
	- Click `Save`
2. Click the API-Key Symbol (Postage Stamp?) to create a API Key and click yes.
   	    
   <img width="600" height="250" alt="image" src="https://github.com/user-attachments/assets/90ae8565-729b-451f-9a78-f61a18a6b05a" />
4. Open the downloaded file and copy the API key and secret
