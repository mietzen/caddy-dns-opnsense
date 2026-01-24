// Mock OPNsense API server for integration testing
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// RequestLog represents a logged HTTP request
type RequestLog struct {
	Timestamp string            `json:"timestamp"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body,omitempty"`
}

// dnsmasqHost represents a dnsmasq host override record
type dnsmasqHost struct {
	UUID   string `json:"uuid"`
	Host   string `json:"host"`
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Descr  string `json:"descr"`
}

// unboundHost represents an unbound host override record
type unboundHost struct {
	UUID        string `json:"uuid"`
	Hostname    string `json:"hostname"`
	Domain      string `json:"domain"`
	Server      string `json:"server"`
	Description string `json:"description"`
}

var (
	requestLogs []RequestLog
	logMutex    sync.Mutex
	logFile     string
	dnsService  string

	// Stateful record tracking
	dnsmasqHosts     = make(map[string]dnsmasqHost)
	unboundHosts     = make(map[string]unboundHost)
	hostsMutex       sync.RWMutex
	uuidCounter      int
	uuidCounterMutex sync.Mutex
)

func generateUUID() string {
	uuidCounterMutex.Lock()
	defer uuidCounterMutex.Unlock()
	uuidCounter++
	return fmt.Sprintf("test-uuid-%03d", uuidCounter)
}

func main() {
	port := flag.Int("port", 8443, "Port to listen on")
	flag.StringVar(&logFile, "log", "requests.json", "File to write request logs")
	flag.StringVar(&dnsService, "service", "dnsmasq", "DNS service to mock: dnsmasq or unbound")
	flag.Parse()

	http.HandleFunc("/", handleRequest)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Mock OPNsense API server starting on %s (service: %s) with TLS", addr, dnsService)

	tlsConfig, err := generateSelfSignedTLSConfig()
	if err != nil {
		log.Fatalf("Failed to generate TLS config: %v", err)
	}

	server := &http.Server{
		Addr:         addr,
		TLSConfig:    tlsConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// generateSelfSignedTLSConfig creates a TLS config with a self-signed certificate
func generateSelfSignedTLSConfig() (*tls.Config, error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Mock OPNsense"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Create TLS certificate
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Read body
	body, _ := io.ReadAll(r.Body)
	defer func() { _ = r.Body.Close() }()

	// Log the request
	headers := make(map[string]string)
	for key, values := range r.Header {
		headers[key] = strings.Join(values, ", ")
	}

	reqLog := RequestLog{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Method:    r.Method,
		Path:      r.URL.Path,
		Headers:   headers,
		Body:      string(body),
	}

	logMutex.Lock()
	requestLogs = append(requestLogs, reqLog)
	writeLogsToFile()
	logMutex.Unlock()

	log.Printf("%s %s", r.Method, r.URL.Path)

	// Route to appropriate handler
	w.Header().Set("Content-Type", "application/json")

	switch {
	case strings.HasPrefix(r.URL.Path, "/api/dnsmasq/"):
		handleDnsmasq(w, r, body)
	case strings.HasPrefix(r.URL.Path, "/api/unbound/"):
		handleUnbound(w, r, body)
	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}
}

func handleDnsmasq(w http.ResponseWriter, r *http.Request, body []byte) {
	path := strings.TrimPrefix(r.URL.Path, "/api/dnsmasq/")

	switch {
	case path == "settings/search_host" && r.Method == http.MethodGet:
		// Return all stored hosts
		hostsMutex.RLock()
		rows := make([]dnsmasqHost, 0, len(dnsmasqHosts))
		for _, h := range dnsmasqHosts {
			rows = append(rows, h)
		}
		hostsMutex.RUnlock()
		log.Printf("search_host returning %d hosts", len(rows))
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"rows": rows,
		})

	case path == "settings/add_host" && r.Method == http.MethodPost:
		// Parse the request body to extract host data
		var hostData struct {
			Host struct {
				Host   string `json:"host"`
				Domain string `json:"domain"`
				IP     string `json:"ip"`
				Descr  string `json:"descr"`
			} `json:"host"`
		}
		if err := json.Unmarshal(body, &hostData); err != nil {
			log.Printf("Error parsing add_host body: %v", err)
		}

		uuid := generateUUID()
		host := dnsmasqHost{
			UUID:   uuid,
			Host:   hostData.Host.Host,
			Domain: hostData.Host.Domain,
			IP:     hostData.Host.IP,
			Descr:  hostData.Host.Descr,
		}

		hostsMutex.Lock()
		dnsmasqHosts[uuid] = host
		hostsMutex.Unlock()

		log.Printf("add_host: %s.%s -> %s (uuid: %s, descr: %s)", host.Host, host.Domain, host.IP, uuid, host.Descr)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"result": "saved",
			"uuid":   uuid,
		})

	case strings.HasPrefix(path, "settings/set_host/") && r.Method == http.MethodPost:
		// Extract UUID from path
		uuid := strings.TrimPrefix(path, "settings/set_host/")

		// Parse the request body to extract host data
		var hostData struct {
			Host struct {
				Host   string `json:"host"`
				Domain string `json:"domain"`
				IP     string `json:"ip"`
				Descr  string `json:"descr"`
			} `json:"host"`
		}
		if err := json.Unmarshal(body, &hostData); err != nil {
			log.Printf("Error parsing set_host body: %v", err)
		}

		host := dnsmasqHost{
			UUID:   uuid,
			Host:   hostData.Host.Host,
			Domain: hostData.Host.Domain,
			IP:     hostData.Host.IP,
			Descr:  hostData.Host.Descr,
		}

		hostsMutex.Lock()
		dnsmasqHosts[uuid] = host
		hostsMutex.Unlock()

		log.Printf("set_host: %s.%s -> %s (uuid: %s, descr: %s)", host.Host, host.Domain, host.IP, uuid, host.Descr)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"result": "saved",
		})

	case strings.HasPrefix(path, "settings/del_host/") && r.Method == http.MethodPost:
		// Extract UUID from path
		uuid := strings.TrimPrefix(path, "settings/del_host/")

		hostsMutex.Lock()
		if host, ok := dnsmasqHosts[uuid]; ok {
			log.Printf("del_host: %s.%s (uuid: %s)", host.Host, host.Domain, uuid)
			delete(dnsmasqHosts, uuid)
		} else {
			log.Printf("del_host: uuid %s not found", uuid)
		}
		hostsMutex.Unlock()

		_ = json.NewEncoder(w).Encode(map[string]string{
			"result": "deleted",
		})

	case path == "service/reconfigure" && r.Method == http.MethodPost:
		log.Printf("reconfigure: current hosts count = %d", len(dnsmasqHosts))
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
		})

	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "endpoint not found"})
	}
}

func handleUnbound(w http.ResponseWriter, r *http.Request, body []byte) {
	path := strings.TrimPrefix(r.URL.Path, "/api/unbound/")

	switch {
	case path == "settings/search_host_override" && r.Method == http.MethodPost:
		// Return all stored hosts
		hostsMutex.RLock()
		rows := make([]unboundHost, 0, len(unboundHosts))
		for _, h := range unboundHosts {
			rows = append(rows, h)
		}
		hostsMutex.RUnlock()
		log.Printf("search_host_override returning %d hosts", len(rows))
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"rows": rows,
		})

	case path == "settings/add_host_override" && r.Method == http.MethodPost:
		// Parse the request body to extract host data
		var hostData struct {
			HostOverride struct {
				Hostname    string `json:"hostname"`
				Domain      string `json:"domain"`
				Server      string `json:"server"`
				Description string `json:"description"`
			} `json:"host_override"`
		}
		if err := json.Unmarshal(body, &hostData); err != nil {
			log.Printf("Error parsing add_host_override body: %v", err)
		}

		uuid := generateUUID()
		host := unboundHost{
			UUID:        uuid,
			Hostname:    hostData.HostOverride.Hostname,
			Domain:      hostData.HostOverride.Domain,
			Server:      hostData.HostOverride.Server,
			Description: hostData.HostOverride.Description,
		}

		hostsMutex.Lock()
		unboundHosts[uuid] = host
		hostsMutex.Unlock()

		log.Printf("add_host_override: %s.%s -> %s (uuid: %s, descr: %s)", host.Hostname, host.Domain, host.Server, uuid, host.Description)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"result": "saved",
			"uuid":   uuid,
		})

	case strings.HasPrefix(path, "settings/set_host_override/") && r.Method == http.MethodPost:
		// Extract UUID from path
		uuid := strings.TrimPrefix(path, "settings/set_host_override/")

		// Parse the request body to extract host data
		var hostData struct {
			HostOverride struct {
				Hostname    string `json:"hostname"`
				Domain      string `json:"domain"`
				Server      string `json:"server"`
				Description string `json:"description"`
			} `json:"host_override"`
		}
		if err := json.Unmarshal(body, &hostData); err != nil {
			log.Printf("Error parsing set_host_override body: %v", err)
		}

		host := unboundHost{
			UUID:        uuid,
			Hostname:    hostData.HostOverride.Hostname,
			Domain:      hostData.HostOverride.Domain,
			Server:      hostData.HostOverride.Server,
			Description: hostData.HostOverride.Description,
		}

		hostsMutex.Lock()
		unboundHosts[uuid] = host
		hostsMutex.Unlock()

		log.Printf("set_host_override: %s.%s -> %s (uuid: %s, descr: %s)", host.Hostname, host.Domain, host.Server, uuid, host.Description)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"result": "saved",
		})

	case strings.HasPrefix(path, "settings/del_host_override/") && r.Method == http.MethodPost:
		// Extract UUID from path
		uuid := strings.TrimPrefix(path, "settings/del_host_override/")

		hostsMutex.Lock()
		if host, ok := unboundHosts[uuid]; ok {
			log.Printf("del_host_override: %s.%s (uuid: %s)", host.Hostname, host.Domain, uuid)
			delete(unboundHosts, uuid)
		} else {
			log.Printf("del_host_override: uuid %s not found", uuid)
		}
		hostsMutex.Unlock()

		_ = json.NewEncoder(w).Encode(map[string]string{
			"result": "deleted",
		})

	case path == "service/reconfigure" && r.Method == http.MethodPost:
		log.Printf("reconfigure: current hosts count = %d", len(unboundHosts))
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
		})

	default:
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "endpoint not found"})
	}
}

func writeLogsToFile() {
	data, err := json.MarshalIndent(requestLogs, "", "  ")
	if err != nil {
		log.Printf("Error marshaling logs: %v", err)
		return
	}
	if err := os.WriteFile(logFile, data, 0644); err != nil {
		log.Printf("Error writing log file: %v", err)
	}
}
