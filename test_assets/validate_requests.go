// Validates that the mock server received expected API requests
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// RequestLog represents a logged HTTP request
type RequestLog struct {
	Timestamp string            `json:"timestamp"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body,omitempty"`
}

// AddHostRequest for dnsmasq
type DnsmasqAddHostRequest struct {
	Host struct {
		Host   string `json:"host"`
		Domain string `json:"domain"`
		IP     string `json:"ip"`
		Descr  string `json:"descr"`
	} `json:"host"`
}

// AddHostOverrideRequest for unbound
type UnboundAddHostRequest struct {
	Host struct {
		Enabled     string `json:"enabled"`
		Hostname    string `json:"hostname"`
		Domain      string `json:"domain"`
		RR          string `json:"rr"`
		Server      string `json:"server"`
		Description string `json:"description"`
	} `json:"host"`
}

func main() {
	logFile := flag.String("log", "requests.json", "Request log file to validate")
	dnsService := flag.String("service", "dnsmasq", "DNS service: dnsmasq or unbound")
	flag.Parse()

	data, err := os.ReadFile(*logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading log file: %v\n", err)
		os.Exit(1)
	}

	var logs []RequestLog
	if err := json.Unmarshal(data, &logs); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing log file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d requests in log\n", len(logs))

	var errors []string

	switch *dnsService {
	case "dnsmasq":
		errors = validateDnsmasq(logs)
	case "unbound":
		errors = validateUnbound(logs)
	default:
		fmt.Fprintf(os.Stderr, "Unknown service: %s\n", *dnsService)
		os.Exit(1)
	}

	if len(errors) > 0 {
		fmt.Println("\nValidation FAILED:")
		for _, e := range errors {
			fmt.Printf("  - %s\n", e)
		}
		os.Exit(1)
	}

	fmt.Println("\nValidation PASSED")
}

func validateDnsmasq(logs []RequestLog) []string {
	var errors []string

	// Expected request sequence:
	// 1. GET /api/dnsmasq/settings/search_host (check existing)
	// 2. POST /api/dnsmasq/settings/add_host (add new record)
	// 3. POST /api/dnsmasq/service/reconfigure

	expectations := []struct {
		method   string
		pathPart string
		validate func(RequestLog) error
	}{
		{"GET", "/api/dnsmasq/settings/search_host", nil},
		{"POST", "/api/dnsmasq/settings/add_host", validateDnsmasqAddHost},
		{"POST", "/api/dnsmasq/service/reconfigure", nil},
	}

	foundExpectations := make([]bool, len(expectations))

	for _, log := range logs {
		// Check for Authorization header
		if _, ok := log.Headers["Authorization"]; !ok {
			errors = append(errors, fmt.Sprintf("Request to %s missing Authorization header", log.Path))
		}

		for i, exp := range expectations {
			if log.Method == exp.method && strings.Contains(log.Path, exp.pathPart) {
				foundExpectations[i] = true
				if exp.validate != nil {
					if err := exp.validate(log); err != nil {
						errors = append(errors, err.Error())
					}
				}
				fmt.Printf("OK: %s %s\n", log.Method, log.Path)
			}
		}
	}

	for i, found := range foundExpectations {
		if !found {
			errors = append(errors, fmt.Sprintf("Missing expected request: %s %s",
				expectations[i].method, expectations[i].pathPart))
		}
	}

	return errors
}

func validateDnsmasqAddHost(log RequestLog) error {
	var req DnsmasqAddHostRequest
	if err := json.Unmarshal([]byte(log.Body), &req); err != nil {
		return fmt.Errorf("invalid add_host request body: %v", err)
	}

	if req.Host.Domain != "example.com" {
		return fmt.Errorf("unexpected domain: got %q, want %q", req.Host.Domain, "example.com")
	}

	if req.Host.IP != "192.168.42.23" {
		return fmt.Errorf("unexpected IP: got %q, want %q", req.Host.IP, "192.168.42.23")
	}

	if req.Host.Descr != "Managed by Caddy Test" {
		return fmt.Errorf("unexpected description: got %q, want %q", req.Host.Descr, "Managed by Caddy Test")
	}

	fmt.Printf("  -> Adding host %q to domain %q with IP %s\n", req.Host.Host, req.Host.Domain, req.Host.IP)
	return nil
}

func validateUnbound(logs []RequestLog) []string {
	var errors []string

	// Expected request sequence:
	// 1. POST /api/unbound/settings/search_host_override (check existing)
	// 2. POST /api/unbound/settings/add_host_override (add new record)
	// 3. POST /api/unbound/service/reconfigure

	expectations := []struct {
		method   string
		pathPart string
		validate func(RequestLog) error
	}{
		{"POST", "/api/unbound/settings/search_host_override", nil},
		{"POST", "/api/unbound/settings/add_host_override", validateUnboundAddHost},
		{"POST", "/api/unbound/service/reconfigure", nil},
	}

	foundExpectations := make([]bool, len(expectations))

	for _, log := range logs {
		// Check for Authorization header
		if _, ok := log.Headers["Authorization"]; !ok {
			errors = append(errors, fmt.Sprintf("Request to %s missing Authorization header", log.Path))
		}

		for i, exp := range expectations {
			if log.Method == exp.method && strings.Contains(log.Path, exp.pathPart) {
				foundExpectations[i] = true
				if exp.validate != nil {
					if err := exp.validate(log); err != nil {
						errors = append(errors, err.Error())
					}
				}
				fmt.Printf("OK: %s %s\n", log.Method, log.Path)
			}
		}
	}

	for i, found := range foundExpectations {
		if !found {
			errors = append(errors, fmt.Sprintf("Missing expected request: %s %s",
				expectations[i].method, expectations[i].pathPart))
		}
	}

	return errors
}

func validateUnboundAddHost(log RequestLog) error {
	var req UnboundAddHostRequest
	if err := json.Unmarshal([]byte(log.Body), &req); err != nil {
		return fmt.Errorf("invalid add_host_override request body: %v", err)
	}

	if req.Host.Domain != "example.com" {
		return fmt.Errorf("unexpected domain: got %q, want %q", req.Host.Domain, "example.com")
	}

	if req.Host.Server != "192.168.42.23" {
		return fmt.Errorf("unexpected IP: got %q, want %q", req.Host.Server, "192.168.42.23")
	}

	if req.Host.Enabled != "1" {
		return fmt.Errorf("unexpected enabled: got %q, want %q", req.Host.Enabled, "1")
	}

	if req.Host.RR != "A" {
		return fmt.Errorf("unexpected RR: got %q, want %q", req.Host.RR, "A")
	}

	if req.Host.Description != "Managed by Caddy Test" {
		return fmt.Errorf("unexpected description: got %q, want %q", req.Host.Description, "Managed by Caddy Test")
	}

	fmt.Printf("  -> Adding host %q to domain %q with IP %s (RR: %s)\n",
		req.Host.Hostname, req.Host.Domain, req.Host.Server, req.Host.RR)
	return nil
}
