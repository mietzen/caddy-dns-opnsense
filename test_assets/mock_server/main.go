// Mock OPNsense API server for integration testing
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
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

var (
	requestLogs []RequestLog
	logMutex    sync.Mutex
	logFile     string
	dnsService  string
)

func main() {
	port := flag.Int("port", 8443, "Port to listen on")
	flag.StringVar(&logFile, "log", "requests.json", "File to write request logs")
	flag.StringVar(&dnsService, "service", "dnsmasq", "DNS service to mock: dnsmasq or unbound")
	flag.Parse()

	http.HandleFunc("/", handleRequest)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Mock OPNsense API server starting on %s (service: %s)", addr, dnsService)

	server := &http.Server{
		Addr:         addr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Read body
	body, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

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
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}
}

func handleDnsmasq(w http.ResponseWriter, r *http.Request, body []byte) {
	path := strings.TrimPrefix(r.URL.Path, "/api/dnsmasq/")

	switch {
	case path == "settings/search_host" && r.Method == http.MethodGet:
		// Return empty list initially - Caddy will add records
		json.NewEncoder(w).Encode(map[string]interface{}{
			"rows": []interface{}{},
		})

	case path == "settings/add_host" && r.Method == http.MethodPost:
		json.NewEncoder(w).Encode(map[string]string{
			"result": "saved",
			"uuid":   "test-uuid-001",
		})

	case strings.HasPrefix(path, "settings/del_host/") && r.Method == http.MethodPost:
		json.NewEncoder(w).Encode(map[string]string{
			"result": "deleted",
		})

	case path == "service/reconfigure" && r.Method == http.MethodPost:
		json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
		})

	default:
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "endpoint not found"})
	}
}

func handleUnbound(w http.ResponseWriter, r *http.Request, body []byte) {
	path := strings.TrimPrefix(r.URL.Path, "/api/unbound/")

	switch {
	case path == "settings/search_host_override" && r.Method == http.MethodPost:
		// Return empty list initially - Caddy will add records
		json.NewEncoder(w).Encode(map[string]interface{}{
			"rows": []interface{}{},
		})

	case path == "settings/add_host_override" && r.Method == http.MethodPost:
		json.NewEncoder(w).Encode(map[string]string{
			"result": "saved",
			"uuid":   "test-uuid-001",
		})

	case strings.HasPrefix(path, "settings/del_host_override/") && r.Method == http.MethodPost:
		json.NewEncoder(w).Encode(map[string]string{
			"result": "deleted",
		})

	case path == "service/reconfigure" && r.Method == http.MethodPost:
		json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
		})

	default:
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "endpoint not found"})
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
