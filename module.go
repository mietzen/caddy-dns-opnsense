package opnsense

import (
	"context"
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
	opnsensednsmasq "github.com/mietzen/libdns-opnsense-dnsmasq"
	opnsenseunbound "github.com/mietzen/libdns-opnsense-unbound"
	"go.uber.org/zap"
)

// dnsProvider is the interface that both dnsmasq and unbound providers implement
type dnsProvider interface {
	libdns.RecordGetter
	libdns.RecordAppender
	libdns.RecordSetter
	libdns.RecordDeleter
}

// Provider lets Caddy read and manipulate DNS records hosted by OPNsense.
type Provider struct {
	// Host is the OPNsense hostname or IP address (e.g., "opnsense.example.com" or "192.168.1.1")
	Host string `json:"host,omitempty"`
	// APIKey is the OPNsense API key
	APIKey string `json:"api_key,omitempty"`
	// APISecretKey is the OPNsense API secret key
	APISecretKey string `json:"api_secret_key,omitempty"`
	// DNSService specifies which DNS service to use: "dnsmasq" or "unbound"
	DNSService string `json:"dns_service,omitempty"`
	// Insecure skips TLS certificate verification (for self-signed certificates)
	Insecure bool `json:"insecure,omitempty"`
	// EntryDescription is set on created host entries (defaults to "Managed by Caddy")
	EntryDescription string `json:"entry_description,omitempty"`

	provider dnsProvider
}

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.opnsense",
		New: func() caddy.Module { return &Provider{} },
	}
}

// Provision sets up the module. Implements caddy.Provisioner.
func (p *Provider) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	p.Host = strings.TrimSpace(repl.ReplaceAll(p.Host, ""))
	p.APIKey = strings.TrimSpace(repl.ReplaceAll(p.APIKey, ""))
	p.APISecretKey = strings.TrimSpace(repl.ReplaceAll(p.APISecretKey, ""))
	p.DNSService = strings.TrimSpace(repl.ReplaceAll(p.DNSService, ""))
	p.EntryDescription = strings.TrimSpace(repl.ReplaceAll(p.EntryDescription, ""))

	switch strings.ToLower(p.DNSService) {
	case "dnsmasq":
		p.provider = &opnsensednsmasq.Provider{
			Host:        p.Host,
			APIKey:      p.APIKey,
			APISecret:   p.APISecretKey,
			Insecure:    p.Insecure,
			Description: p.EntryDescription,
			Logger:      ctx.Logger(),
		}
	case "unbound":
		p.provider = &opnsenseunbound.Provider{
			Host:        p.Host,
			APIKey:      p.APIKey,
			APISecret:   p.APISecretKey,
			Insecure:    p.Insecure,
			Description: p.EntryDescription,
			Logger:      ctx.Logger(),
		}
	default:
		return fmt.Errorf("invalid dns_service %q: must be 'dnsmasq' or 'unbound'", p.DNSService)
	}

	logger := ctx.Logger()

	logger.Info("OPNsense DNS provider initialized",
		zap.String("dns_service", strings.ToLower(p.DNSService)),
	)

	logger.Debug("OPNsense DNS provider configuration",
		zap.String("host", p.Host),
		zap.Bool("insecure", p.Insecure),
		zap.String("entry_description", p.EntryDescription),
	)

	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
//	opnsense {
//	    host <host>
//	    api_key <api_key>
//	    api_secret_key <api_secret_key>
//	    dns_service <dnsmasq|unbound>
//	    insecure
//	    entry_description <description>
//	}
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "host":
				if d.NextArg() {
					p.Host = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "api_key":
				if d.NextArg() {
					p.APIKey = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "api_secret_key":
				if d.NextArg() {
					p.APISecretKey = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "dns_service":
				if d.NextArg() {
					p.DNSService = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			case "insecure":
				p.Insecure = true
				if d.NextArg() {
					return d.ArgErr()
				}
			case "entry_description":
				if d.NextArg() {
					p.EntryDescription = d.Val()
				}
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	if p.Host == "" {
		return d.Err("missing host")
	}
	if p.APIKey == "" {
		return d.Err("missing api_key")
	}
	if p.APISecretKey == "" {
		return d.Err("missing api_secret_key")
	}
	if p.DNSService == "" {
		return d.Err("missing dns_service")
	}
	return nil
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return p.provider.GetRecords(ctx, zone)
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return p.provider.AppendRecords(ctx, zone, records)
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return p.provider.SetRecords(ctx, zone, records)
}

// DeleteRecords deletes the records from the zone.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return p.provider.DeleteRecords(ctx, zone, records)
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
