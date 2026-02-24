// ------------------------------------------------------
// Shortscan v2 - REST API Server
// Integration API for automation and tool chaining
// ------------------------------------------------------

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/bitquark/shortscan/v2/pkg/config"
	"github.com/bitquark/shortscan/v2/pkg/detection"
	"github.com/bitquark/shortscan/v2/pkg/httpengine"
	"github.com/bitquark/shortscan/v2/pkg/result"
)

// Server represents the API server
type Server struct {
	config          *config.ScanConfig
	httpEngine      *httpengine.HTTPEngine
	detectionEngine *detection.DetectionEngine
	resultProcessor *result.ResultProcessor
	server          *http.Server
}

// ScanRequest represents a scan request
type ScanRequest struct {
	URLs       []string          `json:"urls"`
	Headers    map[string]string `json:"headers,omitempty"`
	Options    ScanOptions       `json:"options,omitempty"`
}

// ScanOptions represents scan options
type ScanOptions struct {
	Concurrency  int    `json:"concurrency,omitempty"`
	Timeout      int    `json:"timeout,omitempty"`
	Detection    string `json:"detection,omitempty"`
	Recurse      bool   `json:"recurse,omitempty"`
	VulnCheckOnly bool  `json:"vuln_check_only,omitempty"`
}

// ScanResponse represents a scan response
type ScanResponse struct {
	Success bool                    `json:"success"`
	Message string                  `json:"message,omitempty"`
	Results []result.ScanResult     `json:"results,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// NewServer creates a new API server
func NewServer(cfg *config.ScanConfig) *Server {
	httpEngine := httpengine.NewHTTPEngine(cfg)
	detectionEngine := detection.NewDetectionEngine(cfg, httpEngine)
	resultProcessor := result.NewResultProcessor(cfg)
	
	return &Server{
		config:          cfg,
		httpEngine:      httpEngine,
		detectionEngine: detectionEngine,
		resultProcessor: resultProcessor,
	}
}

// Start starts the API server
func (s *Server) Start(port int) error {
	router := mux.NewRouter()
	
	// API routes
	api := router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/scan", s.handleScan).Methods("POST")
	api.HandleFunc("/scan/{id}", s.handleGetScan).Methods("GET")
	api.HandleFunc("/detect", s.handleDetect).Methods("POST")
	api.HandleFunc("/status", s.handleStatus).Methods("GET")
	api.HandleFunc("/health", s.handleHealth).Methods("GET")
	
	// Middleware
	router.Use(s.loggingMiddleware)
	router.Use(s.authMiddleware)
	
	// Create server
	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	
	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

// handleScan handles scan requests
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	
	if len(req.URLs) == 0 {
		s.sendError(w, http.StatusBadRequest, "No URLs provided", "At least one URL is required")
		return
	}
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	
	results := make([]result.ScanResult, 0)
	
	for _, url := range req.URLs {
		// Detect vulnerability
		detectionResult, err := s.detectionEngine.DetectVulnerability(ctx, url)
		if err != nil {
			continue
		}
		
		scanResult := result.ScanResult{
			TargetURL:  url,
			Vulnerable: detectionResult.Vulnerable,
			StartTime:  time.Now(),
		}
		
		if detectionResult.Vulnerable {
			// Enumerate files
			files, _ := s.detectionEngine.EnumerateFiles(ctx, url, detectionResult)
			scanResult.FilesDiscovered = files
			
			// Create vulnerability info
			vulnInfo := result.VulnerabilityInfo{
				ID:           "IIS-SHORTNAME-001",
				Name:         "IIS Short Filename Enumeration",
				Description:  "Target is vulnerable to IIS short filename enumeration",
				CVSS:         result.CalculateCVSS(len(files), false),
				DiscoveredAt: time.Now(),
				TargetURL:    url,
				Confidence:   detectionResult.Confidence,
			}
			scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vulnInfo)
		}
		
		scanResult.EndTime = time.Now()
		scanResult.Duration = scanResult.EndTime.Sub(scanResult.StartTime)
		
		results = append(results, scanResult)
	}
	
	s.sendJSON(w, http.StatusOK, ScanResponse{
		Success: true,
		Message: fmt.Sprintf("Scanned %d targets", len(req.URLs)),
		Results: results,
	})
}

// handleDetect handles quick vulnerability detection
func (s *Server) handleDetect(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	
	if len(req.URLs) == 0 {
		s.sendError(w, http.StatusBadRequest, "No URLs provided", "At least one URL is required")
		return
	}
	
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	
	type DetectResult struct {
		URL        string  `json:"url"`
		Vulnerable bool    `json:"vulnerable"`
		Confidence float64 `json:"confidence"`
		Method     string  `json:"method"`
	}
	
	results := make([]DetectResult, 0)
	
	for _, url := range req.URLs {
		detectionResult, err := s.detectionEngine.DetectVulnerability(ctx, url)
		if err != nil {
			results = append(results, DetectResult{URL: url, Vulnerable: false})
			continue
		}
		
		results = append(results, DetectResult{
			URL:        url,
			Vulnerable: detectionResult.Vulnerable,
			Confidence: detectionResult.Confidence,
			Method:     detectionResult.Method,
		})
	}
	
	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"results": results,
	})
}

// handleGetScan handles getting scan results by ID
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["id"]
	
	// TODO: Implement scan result storage and retrieval
	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"scan_id": scanID,
		"message": "Scan result retrieval not yet implemented",
	})
}

// handleStatus handles status requests
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	stats := s.httpEngine.GetStats()
	
	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"version":   config.Version,
		"build":     config.BuildDate,
		"statistics": stats,
	})
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.sendJSON(w, http.StatusOK, map[string]interface{}{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// loggingMiddleware logs all requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Wrap response writer to capture status
		wrapped := &responseWriter{ResponseWriter: w}
		
		next.ServeHTTP(wrapped, r)
		
		duration := time.Since(start)
		fmt.Printf("[%s] %s %s %d %v\n",
			time.Now().Format("2006-01-02 15:04:05"),
			r.Method,
			r.URL.Path,
			wrapped.status,
			duration,
		)
	})
}

// authMiddleware handles API authentication
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health endpoint
		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}
		
		// Check API key if configured
		if s.config.APIKey != "" {
			apiKey := r.Header.Get("X-API-Key")
			if apiKey != s.config.APIKey {
				s.sendError(w, http.StatusUnauthorized, "Unauthorized", "Invalid API key")
				return
			}
		}
		
		next.ServeHTTP(w, r)
	})
}

// sendJSON sends a JSON response
func (s *Server) sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// sendError sends an error response
func (s *Server) sendError(w http.ResponseWriter, status int, error, message string) {
	s.sendJSON(w, status, ErrorResponse{
		Error:   error,
		Message: message,
	})
}

// responseWriter wraps http.ResponseWriter to capture status
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}
