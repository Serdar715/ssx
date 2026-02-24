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
	"sync"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/bitquark/shortscan/v2/pkg/config"
	"github.com/bitquark/shortscan/v2/pkg/detection"
	"github.com/bitquark/shortscan/v2/pkg/httpengine"
	"github.com/bitquark/shortscan/v2/pkg/result"
)

// Server represents the API server.
type Server struct {
	cfg             *config.ScanConfig
	httpEngine      *httpengine.HTTPEngine
	detectionEngine *detection.DetectionEngine
	resultProcessor *result.ResultProcessor
	server          *http.Server
}

// ScanRequest represents a scan request payload.
type ScanRequest struct {
	URLs    []string          `json:"urls"`
	Headers map[string]string `json:"headers,omitempty"`
	Options ScanOptions       `json:"options,omitempty"`
}

// ScanOptions represents optional overrides for a single scan request.
type ScanOptions struct {
	Concurrency   int    `json:"concurrency,omitempty"`
	Timeout       int    `json:"timeout,omitempty"`
	Detection     string `json:"detection,omitempty"`
	Recurse       bool   `json:"recurse,omitempty"`
	VulnCheckOnly bool   `json:"vuln_check_only,omitempty"`
}

// ScanResponse wraps results returned by /api/v1/scan.
type ScanResponse struct {
	Success bool                `json:"success"`
	Message string              `json:"message,omitempty"`
	Results []result.ScanResult `json:"results,omitempty"`
}

// ErrorResponse wraps error information returned on failures.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// detectResult is used internally by /api/v1/detect.
type detectResult struct {
	URL        string  `json:"url"`
	Vulnerable bool    `json:"vulnerable"`
	Confidence float64 `json:"confidence"`
	Method     string  `json:"method"`
}

// NewServer creates a new API server and its dependencies.
func NewServer(cfg *config.ScanConfig) (*Server, error) {
	httpEngine := httpengine.NewHTTPEngine(cfg)
	detectionEngine := detection.NewDetectionEngine(cfg, httpEngine)

	resultProcessor, err := result.NewResultProcessor(cfg)
	if err != nil {
		return nil, fmt.Errorf("initialise result processor: %w", err)
	}

	return &Server{
		cfg:             cfg,
		httpEngine:      httpEngine,
		detectionEngine: detectionEngine,
		resultProcessor: resultProcessor,
	}, nil
}

// Start registers routes and starts listening on the given port.
// It blocks until the server is stopped; use Shutdown to stop it gracefully.
func (s *Server) Start(port int) error {
	router := mux.NewRouter()

	apiRouter := router.PathPrefix("/api/v1").Subrouter()
	apiRouter.HandleFunc("/scan", s.handleScan).Methods(http.MethodPost)
	apiRouter.HandleFunc("/scan/{id}", s.handleGetScan).Methods(http.MethodGet)
	apiRouter.HandleFunc("/detect", s.handleDetect).Methods(http.MethodPost)
	apiRouter.HandleFunc("/status", s.handleStatus).Methods(http.MethodGet)
	apiRouter.HandleFunc("/health", s.handleHealth).Methods(http.MethodGet)

	router.Use(s.loggingMiddleware)
	router.Use(s.authMiddleware)

	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s.server.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

// handleScan handles POST /api/v1/scan — scans all URLs concurrently.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if len(req.URLs) == 0 {
		s.sendError(w, http.StatusBadRequest, "missing_urls", "at least one URL is required")
		return
	}

	// 5-minute upper bound for the entire scan batch.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	type indexed struct {
		pos    int
		result result.ScanResult
	}

	resultsCh := make(chan indexed, len(req.URLs))
	var wg sync.WaitGroup

	for pos, rawURL := range req.URLs {
		wg.Add(1)
		go func(idx int, targetURL string) {
			defer wg.Done()

			scanResult := result.ScanResult{
				TargetURL: targetURL,
				StartTime: time.Now(),
			}

			detectionResult, err := s.detectionEngine.DetectVulnerability(ctx, targetURL)
			if err != nil {
				scanResult.EndTime = time.Now()
				scanResult.Duration = scanResult.EndTime.Sub(scanResult.StartTime)
				resultsCh <- indexed{pos: idx, result: scanResult}
				return
			}

			scanResult.Vulnerable = detectionResult.Vulnerable

			if detectionResult.Vulnerable {
				files, _ := s.detectionEngine.EnumerateFiles(ctx, targetURL, detectionResult)
				scanResult.FilesDiscovered = files

				vulnInfo := result.VulnerabilityInfo{
					ID:           "IIS-SHORTNAME-001",
					Name:         "IIS Short Filename Enumeration",
					Description:  "Target is vulnerable to IIS short filename enumeration",
					CVSS:         result.CalculateCVSS(len(files), false),
					FilesExposed: files,
					DiscoveredAt: time.Now(),
					TargetURL:    targetURL,
					Confidence:   detectionResult.Confidence,
				}
				scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vulnInfo)
			}

			scanResult.EndTime = time.Now()
			scanResult.Duration = scanResult.EndTime.Sub(scanResult.StartTime)
			resultsCh <- indexed{pos: idx, result: scanResult}
		}(pos, rawURL)
	}

	// Close channel once all goroutines finish.
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Collect and order results.
	ordered := make([]result.ScanResult, len(req.URLs))
	for item := range resultsCh {
		ordered[item.pos] = item.result
	}

	s.sendJSON(w, http.StatusOK, ScanResponse{
		Success: true,
		Message: fmt.Sprintf("scanned %d targets", len(req.URLs)),
		Results: ordered,
	})
}

// handleDetect handles POST /api/v1/detect — quick vulnerability check, no enumeration.
func (s *Server) handleDetect(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.sendError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	if len(req.URLs) == 0 {
		s.sendError(w, http.StatusBadRequest, "missing_urls", "at least one URL is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()

	type response struct {
		Success bool           `json:"success"`
		Results []detectResult `json:"results"`
	}

	resultsCh := make(chan detectResult, len(req.URLs))
	var wg sync.WaitGroup

	for _, rawURL := range req.URLs {
		wg.Add(1)
		go func(targetURL string) {
			defer wg.Done()

			detResult, err := s.detectionEngine.DetectVulnerability(ctx, targetURL)
			if err != nil {
				resultsCh <- detectResult{URL: targetURL, Vulnerable: false}
				return
			}
			resultsCh <- detectResult{
				URL:        targetURL,
				Vulnerable: detResult.Vulnerable,
				Confidence: detResult.Confidence,
				Method:     detResult.Method,
			}
		}(rawURL)
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	results := make([]detectResult, 0, len(req.URLs))
	for res := range resultsCh {
		results = append(results, res)
	}

	s.sendJSON(w, http.StatusOK, response{Success: true, Results: results})
}

// handleGetScan handles GET /api/v1/scan/{id}.
// TODO: Implement persistent scan result storage.
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	s.sendJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"scan_id": vars["id"],
		"message": "scan result retrieval not yet implemented",
	})
}

// handleStatus handles GET /api/v1/status.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	stats := s.httpEngine.GetStats()
	s.sendJSON(w, http.StatusOK, map[string]any{
		"success":    true,
		"version":    config.Version,
		"build":      config.BuildDate,
		"statistics": stats,
	})
}

// handleHealth handles GET /api/v1/health.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.sendJSON(w, http.StatusOK, map[string]any{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// loggingMiddleware logs every request with method, path, status, and duration.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		log.Infof("[API] %s %s %d %v", r.Method, r.URL.Path, wrapped.status, time.Since(start))
	})
}

// authMiddleware enforces API key authentication when cfg.APIKey is set.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health endpoint is always public.
		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		if s.cfg.APIKey != "" {
			if r.Header.Get("X-API-Key") != s.cfg.APIKey {
				s.sendError(w, http.StatusUnauthorized, "unauthorized", "invalid API key")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// sendJSON writes a JSON response, logging any encoding errors.
func (s *Server) sendJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Errorf("JSON encode failed (status %d): %v", status, err)
	}
}

// sendError writes a structured JSON error response.
func (s *Server) sendError(w http.ResponseWriter, status int, errCode, message string) {
	s.sendJSON(w, status, ErrorResponse{Error: errCode, Message: message})
}

// statusRecorder wraps http.ResponseWriter to capture the response status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(status int) {
	sr.status = status
	sr.ResponseWriter.WriteHeader(status)
}
