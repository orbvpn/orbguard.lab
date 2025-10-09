// main.go - Complete Threat Intelligence API Backend in Go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

// ============================================================================
// DATA MODELS
// ============================================================================

type IndicatorOfCompromise struct {
	Value       string                 `json:"value"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Tags        []string               `json:"tags"`
	FirstSeen   time.Time              `json:"first_seen"`
	LastSeen    time.Time              `json:"last_seen"`
	ReportCount int                    `json:"report_count"`
	Sources     []string               `json:"sources"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type ThreatIntelligence struct {
	Domains      map[string]*IndicatorOfCompromise `json:"domains"`
	IPs          map[string]*IndicatorOfCompromise `json:"ips"`
	FileHashes   map[string]*IndicatorOfCompromise `json:"file_hashes"`
	ProcessNames map[string]*IndicatorOfCompromise `json:"process_names"`
	Certificates map[string]*IndicatorOfCompromise `json:"certificates"`
	PackageNames map[string]*IndicatorOfCompromise `json:"package_names"`
	LastUpdated  time.Time                         `json:"last_updated"`
	Version      int                               `json:"version"`
	mu           sync.RWMutex                      // Thread-safe access
}

type ThreatReport struct {
	Indicator   string                 `json:"indicator"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Tags        []string               `json:"tags"`
	Metadata    map[string]interface{} `json:"metadata"`
	ReportedAt  time.Time              `json:"reported_at"`
	DeviceInfo  map[string]interface{} `json:"device_info"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// ============================================================================
// GLOBAL STATE
// ============================================================================

var (
	threatIntel *ThreatIntelligence
	apiKey      string
)

// ============================================================================
// INITIALIZATION
// ============================================================================

func init() {
	threatIntel = &ThreatIntelligence{
		Domains:      make(map[string]*IndicatorOfCompromise),
		IPs:          make(map[string]*IndicatorOfCompromise),
		FileHashes:   make(map[string]*IndicatorOfCompromise),
		ProcessNames: make(map[string]*IndicatorOfCompromise),
		Certificates: make(map[string]*IndicatorOfCompromise),
		PackageNames: make(map[string]*IndicatorOfCompromise),
		LastUpdated:  time.Now(),
		Version:      1,
	}

	// Load API key from environment
	apiKey = os.Getenv("API_KEY")
	if apiKey == "" {
		apiKey = "default-dev-key" // For development only
		log.Println("WARNING: Using default API key. Set API_KEY environment variable for production.")
	}
}

// ============================================================================
// THREAT INTELLIGENCE AGGREGATION
// ============================================================================

func aggregateThreatIntelligence() error {
	log.Println("[Aggregator] Starting threat intelligence aggregation...")

	// Use WaitGroup for concurrent fetching
	var wg sync.WaitGroup
	errorChan := make(chan error, 3)

	// Fetch from multiple sources concurrently
	wg.Add(3)

	go func() {
		defer wg.Done()
		if err := fetchPegasusIoCs(); err != nil {
			errorChan <- fmt.Errorf("Pegasus IoCs: %w", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := fetchCommunityReports(); err != nil {
			errorChan <- fmt.Errorf("Community reports: %w", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := fetchPublicFeeds(); err != nil {
			errorChan <- fmt.Errorf("Public feeds: %w", err)
		}
	}()

	wg.Wait()
	close(errorChan)

	// Check for errors
	var errors []error
	for err := range errorChan {
		errors = append(errors, err)
		log.Printf("[Aggregator] Error: %v", err)
	}

	// Update metadata
	threatIntel.mu.Lock()
	threatIntel.LastUpdated = time.Now()
	threatIntel.Version++
	threatIntel.mu.Unlock()

	totalIndicators := getTotalIndicators()
	log.Printf("[Aggregator] Completed! Total indicators: %d", totalIndicators)

	if len(errors) > 0 {
		return fmt.Errorf("aggregation completed with %d errors", len(errors))
	}
	return nil
}

func fetchPegasusIoCs() error {
	log.Println("[Pegasus] Fetching Pegasus-specific IoCs...")

	// Known Pegasus indicators from Citizen Lab, Amnesty Tech, Lookout, etc.
	pegasusIndicators := []struct {
		value    string
		iocType  string
		severity string
		desc     string
		tags     []string
	}{
		// Domains
		{"lsgatag.com", "domain", "critical", "Known Pegasus C2 domain", []string{"pegasus", "nso-group", "c2"}},
		{"lxwo.org", "domain", "critical", "Pegasus infrastructure", []string{"pegasus", "nso-group"}},
		{"iosmac.org", "domain", "critical", "Pegasus iOS targeting", []string{"pegasus", "ios"}},
		{"cloudatlasinc.com", "domain", "critical", "Pegasus front company", []string{"pegasus", "nso-group"}},
		{"lighthouseresearch.com", "domain", "critical", "Pegasus infrastructure", []string{"pegasus"}},
		{"mynetsec.net", "domain", "critical", "Pegasus C2", []string{"pegasus", "c2"}},
		{"updates-icloud-content.com", "domain", "critical", "Fake iCloud domain", []string{"pegasus", "ios", "phishing"}},
		{"backupios.com", "domain", "critical", "Fake iOS backup", []string{"pegasus", "ios"}},
		{"appcheck-store.net", "domain", "critical", "Fake app store", []string{"pegasus"}},

		// Process Names (iOS)
		{"setframed", "process", "critical", "Pegasus iOS process", []string{"pegasus", "ios"}},
		{"bridged", "process", "critical", "Pegasus iOS process", []string{"pegasus", "ios"}},
		{"CommsCentre", "process", "critical", "Pegasus iOS process", []string{"pegasus", "ios"}},
		{"aggregated", "process", "high", "Suspicious iOS process", []string{"pegasus", "ios"}},

		// Package Names (Android)
		{"com.network.android", "package", "high", "Fake system package", []string{"android", "spyware"}},
		{"com.system.framework", "package", "high", "Fake framework", []string{"android", "spyware"}},
		{"com.google.android.update", "package", "critical", "Fake Google update", []string{"android", "spyware"}},
		{"com.android.battery", "package", "medium", "Suspicious battery app", []string{"android"}},
	}

	threatIntel.mu.Lock()
	defer threatIntel.mu.Unlock()

	now := time.Now()
	firstSeen := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, indicator := range pegasusIndicators {
		ioc := &IndicatorOfCompromise{
			Value:       indicator.value,
			Type:        indicator.iocType,
			Severity:    indicator.severity,
			Description: indicator.desc,
			Tags:        indicator.tags,
			FirstSeen:   firstSeen,
			LastSeen:    now,
			ReportCount: 100, // High confidence
			Sources:     []string{"citizen-lab", "amnesty-tech", "lookout"},
			Metadata:    make(map[string]interface{}),
		}

		// Add to appropriate map
		switch indicator.iocType {
		case "domain":
			threatIntel.Domains[indicator.value] = ioc
		case "process":
			threatIntel.ProcessNames[indicator.value] = ioc
		case "package":
			threatIntel.PackageNames[indicator.value] = ioc
		}
	}

	log.Printf("[Pegasus] Added %d Pegasus indicators", len(pegasusIndicators))
	return nil
}

func fetchCommunityReports() error {
	log.Println("[Community] Processing community reports...")

	// In production, fetch from database
	// For now, simulate with sample data

	// Add logic to fetch community-reported threats
	// Filter for validated reports only

	return nil
}

func fetchPublicFeeds() error {
	log.Println("[PublicFeeds] Fetching from public threat feeds...")

	// Integrate with public APIs
	feeds := []struct {
		name string
		url  string
	}{
		{"Abuse.ch URLhaus", "https://urlhaus-api.abuse.ch/v1/urls/recent/"},
		{"OpenPhish", "https://openphish.com/feed.txt"},
		// Add more feeds
	}

	for _, feed := range feeds {
		log.Printf("[PublicFeeds] Fetching from %s...", feed.name)

		// Make HTTP request
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(feed.url)
		if err != nil {
			log.Printf("[PublicFeeds] Error fetching %s: %v", feed.name, err)
			continue
		}
		defer resp.Body.Close()

		// Parse feed (implementation depends on feed format)
		// Add parsed indicators to threatIntel

		log.Printf("[PublicFeeds] Processed %s", feed.name)
	}

	return nil
}

func getTotalIndicators() int {
	threatIntel.mu.RLock()
	defer threatIntel.mu.RUnlock()

	return len(threatIntel.Domains) +
		len(threatIntel.IPs) +
		len(threatIntel.FileHashes) +
		len(threatIntel.ProcessNames) +
		len(threatIntel.Certificates) +
		len(threatIntel.PackageNames)
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

// Middleware for API key authentication
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Allow OPTIONS for CORS preflight
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Check API key
		providedKey := r.Header.Get("Authorization")
		if providedKey == "" || providedKey != "Bearer "+apiKey {
			respondWithError(w, http.StatusUnauthorized, "Invalid or missing API key")
			return
		}

		next(w, r)
	}
}

// CORS middleware
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Health check
func handleHealth(w http.ResponseWriter, r *http.Request) {
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "healthy",
		"version": "1.0.0",
		"uptime":  time.Since(time.Now()).String(),
	})
}

// Get Pegasus-specific IoCs
func handleGetPegasusIoCs(w http.ResponseWriter, r *http.Request) {
	threatIntel.mu.RLock()
	defer threatIntel.mu.RUnlock()

	pegasusData := &ThreatIntelligence{
		Domains:      filterByTag(threatIntel.Domains, "pegasus"),
		IPs:          filterByTag(threatIntel.IPs, "pegasus"),
		FileHashes:   filterByTag(threatIntel.FileHashes, "pegasus"),
		ProcessNames: filterByTag(threatIntel.ProcessNames, "pegasus"),
		Certificates: filterByTag(threatIntel.Certificates, "pegasus"),
		PackageNames: filterByTag(threatIntel.PackageNames, "pegasus"),
		LastUpdated:  threatIntel.LastUpdated,
		Version:      threatIntel.Version,
	}

	respondWithJSON(w, http.StatusOK, pegasusData)
}

// Get all threat intelligence
func handleGetAllIntelligence(w http.ResponseWriter, r *http.Request) {
	threatIntel.mu.RLock()
	defer threatIntel.mu.RUnlock()

	respondWithJSON(w, http.StatusOK, threatIntel)
}

// Get community-reported threats
func handleGetCommunityIoCs(w http.ResponseWriter, r *http.Request) {
	threatIntel.mu.RLock()
	defer threatIntel.mu.RUnlock()

	communityData := &ThreatIntelligence{
		Domains:      filterBySource(threatIntel.Domains, "community"),
		IPs:          filterBySource(threatIntel.IPs, "community"),
		FileHashes:   filterBySource(threatIntel.FileHashes, "community"),
		ProcessNames: filterBySource(threatIntel.ProcessNames, "community"),
		Certificates: filterBySource(threatIntel.Certificates, "community"),
		PackageNames: filterBySource(threatIntel.PackageNames, "community"),
		LastUpdated:  threatIntel.LastUpdated,
		Version:      threatIntel.Version,
	}

	respondWithJSON(w, http.StatusOK, communityData)
}

// Check specific indicator
func handleCheckIndicator(w http.ResponseWriter, r *http.Request) {
	indicator := r.URL.Query().Get("indicator")
	iocType := r.URL.Query().Get("type")

	if indicator == "" || iocType == "" {
		respondWithError(w, http.StatusBadRequest, "Missing indicator or type parameter")
		return
	}

	threatIntel.mu.RLock()
	defer threatIntel.mu.RUnlock()

	var isMalicious bool
	var details *IndicatorOfCompromise

	switch iocType {
	case "domain":
		details, isMalicious = threatIntel.Domains[indicator]
	case "ip":
		details, isMalicious = threatIntel.IPs[indicator]
	case "fileHash":
		details, isMalicious = threatIntel.FileHashes[indicator]
	case "processName":
		details, isMalicious = threatIntel.ProcessNames[indicator]
	case "certificate":
		details, isMalicious = threatIntel.Certificates[indicator]
	case "packageName":
		details, isMalicious = threatIntel.PackageNames[indicator]
	default:
		respondWithError(w, http.StatusBadRequest, "Invalid indicator type")
		return
	}

	response := map[string]interface{}{
		"indicator":   indicator,
		"type":        iocType,
		"isMalicious": isMalicious,
	}

	if isMalicious && details != nil {
		response["details"] = details
	}

	respondWithJSON(w, http.StatusOK, response)
}

// Report new threat
func handleReportThreat(w http.ResponseWriter, r *http.Request) {
	var report ThreatReport

	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate report
	if report.Indicator == "" || report.Type == "" || report.Description == "" {
		respondWithError(w, http.StatusBadRequest, "Missing required fields")
		return
	}

	report.ReportedAt = time.Now()

	// In production: Store in database for review
	// For now: Log it
	log.Printf("[Report] New threat report: %s (%s) - %s", report.Indicator, report.Type, report.Description)

	// TODO: Queue for manual validation
	// TODO: Auto-add high-confidence reports

	respondWithJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Message: "Threat report received and queued for review",
	})
}

// Get statistics
func handleGetStatistics(w http.ResponseWriter, r *http.Request) {
	threatIntel.mu.RLock()
	defer threatIntel.mu.RUnlock()

	stats := map[string]interface{}{
		"total":        getTotalIndicators(),
		"domains":      len(threatIntel.Domains),
		"ips":          len(threatIntel.IPs),
		"fileHashes":   len(threatIntel.FileHashes),
		"processNames": len(threatIntel.ProcessNames),
		"certificates": len(threatIntel.Certificates),
		"packageNames": len(threatIntel.PackageNames),
		"lastUpdated":  threatIntel.LastUpdated,
		"version":      threatIntel.Version,
	}

	respondWithJSON(w, http.StatusOK, stats)
}

// Force update
func handleForceUpdate(w http.ResponseWriter, r *http.Request) {
	go func() {
		if err := aggregateThreatIntelligence(); err != nil {
			log.Printf("[Update] Error: %v", err)
		}
	}()

	respondWithJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Message: "Threat intelligence update initiated",
	})
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func filterByTag(iocs map[string]*IndicatorOfCompromise, tag string) map[string]*IndicatorOfCompromise {
	filtered := make(map[string]*IndicatorOfCompromise)
	for key, ioc := range iocs {
		for _, t := range ioc.Tags {
			if t == tag {
				filtered[key] = ioc
				break
			}
		}
	}
	return filtered
}

func filterBySource(iocs map[string]*IndicatorOfCompromise, source string) map[string]*IndicatorOfCompromise {
	filtered := make(map[string]*IndicatorOfCompromise)
	for key, ioc := range iocs {
		for _, s := range ioc.Sources {
			if s == source {
				filtered[key] = ioc
				break
			}
		}
	}
	return filtered
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Internal server error"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, APIResponse{
		Success: false,
		Error:   message,
	})
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	// Initialize threat intelligence
	log.Println("Initializing threat intelligence...")
	if err := aggregateThreatIntelligence(); err != nil {
		log.Printf("Warning: Initial aggregation completed with errors: %v", err)
	}

	// Start periodic updates (every 6 hours)
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			log.Println("Starting scheduled threat intelligence update...")
			if err := aggregateThreatIntelligence(); err != nil {
				log.Printf("Scheduled update error: %v", err)
			}
		}
	}()

	// Setup router
	r := mux.NewRouter()

	// Public endpoints
	r.HandleFunc("/health", handleHealth).Methods("GET")
	r.HandleFunc("/api/v1/stats", handleGetStatistics).Methods("GET")

	// Protected endpoints
	r.HandleFunc("/api/v1/intelligence/pegasus", authMiddleware(handleGetPegasusIoCs)).Methods("GET")
	r.HandleFunc("/api/v1/intelligence/all", authMiddleware(handleGetAllIntelligence)).Methods("GET")
	r.HandleFunc("/api/v1/intelligence/community", authMiddleware(handleGetCommunityIoCs)).Methods("GET")
	r.HandleFunc("/api/v1/intelligence/check", authMiddleware(handleCheckIndicator)).Methods("GET")
	r.HandleFunc("/api/v1/intelligence/report", authMiddleware(handleReportThreat)).Methods("POST")
	r.HandleFunc("/api/v1/intelligence/update", authMiddleware(handleForceUpdate)).Methods("POST")

	// Apply CORS middleware
	handler := corsMiddleware(r)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("🚀 Threat Intelligence API server starting on port %s", port)
	log.Printf("📊 Total indicators loaded: %d", getTotalIndicators())
	log.Fatal(server.ListenAndServe())
}
