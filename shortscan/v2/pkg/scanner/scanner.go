// ------------------------------------------------------
// Shortscan v2 - Main Scanner
// Advanced IIS short filename enumeration tool
// ------------------------------------------------------

package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"

	"github.com/bitquark/shortscan/v2/pkg/config"
	"github.com/bitquark/shortscan/v2/pkg/detection"
	"github.com/bitquark/shortscan/v2/pkg/httpengine"
	"github.com/bitquark/shortscan/v2/pkg/result"
)

// Scanner is the main scanner struct
type Scanner struct {
	config          *config.ScanConfig
	httpEngine      *httpengine.HTTPEngine
	detectionEngine *detection.DetectionEngine
	resultProcessor *result.ResultProcessor
	
	// Progress tracking
	totalTargets    int
	scannedTargets  int32
	mu              sync.RWMutex
}

// NewScanner creates a new scanner
func NewScanner(cfg *config.ScanConfig) *Scanner {
	httpEngine := httpengine.NewHTTPEngine(cfg)
	detectionEngine := detection.NewDetectionEngine(cfg, httpEngine)
	resultProcessor := result.NewResultProcessor(cfg)
	
	return &Scanner{
		config:          cfg,
		httpEngine:      httpEngine,
		detectionEngine: detectionEngine,
		resultProcessor: resultProcessor,
	}
}

// Scan starts the scanning process
func (s *Scanner) Scan(ctx context.Context, urls []string) error {
	// Normalize and prepare URLs
	targets := s.prepareURLs(urls)
	s.totalTargets = len(targets)
	
	// Print banner
	s.printBanner()
	
	// Create semaphore for concurrency control
	sem := make(chan struct{}, s.config.Concurrency)
	
	// WaitGroup for synchronization
	var wg sync.WaitGroup
	
	// Scan each target
	for _, target := range targets {
		wg.Add(1)
		
		go func(url string) {
			defer wg.Done()
			
			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()
			
			// Scan single target
			s.scanTarget(ctx, url)
		}(target)
	}
	
	// Wait for all scans to complete
	wg.Wait()
	
	// Print summary
	s.printSummary()
	
	return nil
}

// prepareURLs normalizes and prepares URLs for scanning
func (s *Scanner) prepareURLs(urls []string) []string {
	prepared := make([]string, 0, len(urls))
	
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if url == "" {
			continue
		}
		
		// Add protocol if missing
		if !strings.Contains(url, "://") {
			url = "https://" + url
		}
		
		// Remove trailing slash
		url = strings.TrimSuffix(url, "/")
		
		prepared = append(prepared, url)
	}
	
	return prepared
}

// scanTarget scans a single target
func (s *Scanner) scanTarget(ctx context.Context, targetURL string) {
	startTime := time.Now()
	
	scanResult := &result.ScanResult{
		TargetURL:    targetURL,
		Vulnerable:   false,
		StartTime:    startTime,
		FilesDiscovered: make([]detection.FileInfo, 0),
		Vulnerabilities: make([]result.VulnerabilityInfo, 0),
	}
	
	// Get server info
	serverInfo := s.getServerInfo(ctx, targetURL)
	scanResult.ServerInfo = serverInfo
	
	// Detect vulnerability
	detectionResult, err := s.detectionEngine.DetectVulnerability(ctx, targetURL)
	if err != nil {
		scanResult.EndTime = time.Now()
		scanResult.Duration = scanResult.EndTime.Sub(startTime)
		s.resultProcessor.AddResult(scanResult)
		return
	}
	
	scanResult.Vulnerable = detectionResult.Vulnerable
	
	if detectionResult.Vulnerable {
		// Create vulnerability info
		vulnInfo := result.VulnerabilityInfo{
			ID:          "IIS-SHORTNAME-001",
			CVE:         "CVE-2025-46294",
			Name:        "IIS Short Filename Enumeration",
			Description: "The target is vulnerable to IIS short filename enumeration, allowing discovery of hidden files and directories",
			CVSS:        result.CalculateCVSS(0, false),
			Remediation: "Disable 8.3 filename creation by setting NtfsDisable8dot3NameCreation to 1 in the registry",
			References: []string{
				"https://techcommunity.microsoft.com/t5/iis-support-blog/iis-short-name-enumeration/ba-p/3951320",
				"https://nvd.nist.gov/vuln/detail/CVE-2025-46294",
			},
			DiscoveredAt: time.Now(),
			TargetURL:    targetURL,
			Confidence:   detectionResult.Confidence,
		}
		scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vulnInfo)
		
		// Enumerate files if not just checking vulnerability
		if !s.config.VulnCheckOnly {
			files, err := s.detectionEngine.EnumerateFiles(ctx, targetURL, detectionResult)
			if err == nil {
				scanResult.FilesDiscovered = files
				vulnInfo.FilesExposed = files
				vulnInfo.CVSS = result.CalculateCVSS(len(files), s.hasSensitiveFiles(files))
			}
		}
	}
	
	// Finalize result
	scanResult.EndTime = time.Now()
	scanResult.Duration = scanResult.EndTime.Sub(startTime)
	
	// Get HTTP stats
	stats := s.httpEngine.GetStats()
	scanResult.Statistics = result.ScanStatistics{
		TotalRequests:   stats.TotalRequests,
		SuccessRequests: stats.SuccessRequests,
		FailedRequests:  stats.FailedRequests,
		Retries:         stats.Retries,
		BytesSent:       stats.BytesSent,
		BytesReceived:   stats.BytesReceived,
		AvgLatency:      stats.AvgLatency,
		MinLatency:      stats.MinLatency,
		MaxLatency:      stats.MaxLatency,
	}
	
	// Add result
	s.resultProcessor.AddResult(scanResult)
}

// getServerInfo retrieves server information
func (s *Scanner) getServerInfo(ctx context.Context, targetURL string) string {
	resp, err := s.httpEngine.Request(ctx, "GET", targetURL+"/", nil)
	if err != nil {
		return "<unknown>"
	}
	
	var info string
	
	// Get Server header
	if server := resp.Header.Get("Server"); server != "" {
		info = server
	} else {
		info = "<unknown>"
	}
	
	// Add ASP.NET version if present
	if aspNet := resp.Header.Get("X-Aspnet-Version"); aspNet != "" {
		info += fmt.Sprintf(" (ASP.NET v%s)", aspNet)
	}
	
	return info
}

// hasSensitiveFiles checks if any discovered files are sensitive
func (s *Scanner) hasSensitiveFiles(files []detection.FileInfo) bool {
	sensitivePatterns := []string{
		"web.config", "password", "secret", "key", "credential",
		"backup", "db", "database", "admin", "config",
		".bak", ".sql", ".mdb", ".log", ".xml",
	}
	
	for _, file := range files {
		lowerName := strings.ToLower(file.FullName)
		for _, pattern := range sensitivePatterns {
			if strings.Contains(lowerName, pattern) {
				return true
			}
		}
	}
	
	return false
}

// printBanner prints the scanner banner
func (s *Scanner) printBanner() {
	if s.config.Quiet {
		return
	}
	
	banner := color.New(color.FgBlue, color.Bold).Sprint("🌀 Shortscan v"+config.Version) +
		" · " + color.New(color.FgWhite, color.Bold).Sprint("Advanced IIS Short Filename Enumeration")
	
	fmt.Println(banner)
	fmt.Printf("Targets: %d | Concurrency: %d | Timeout: %v\n",
		s.totalTargets, s.config.Concurrency, s.config.Timeout)
}

// printSummary prints the scan summary
func (s *Scanner) printSummary() {
	if s.config.Quiet {
		return
	}
	
	fmt.Println("\n" + strings.Repeat("═", 80))
	fmt.Println(s.resultProcessor.GetSummary())
	
	// Print statistics
	stats := s.httpEngine.GetStats()
	fmt.Printf("Statistics: %d requests, %d retries, %d bytes sent, %d bytes received\n",
		stats.TotalRequests, stats.Retries, stats.BytesSent, stats.BytesReceived)
}

// Close closes the scanner and cleans up resources
func (s *Scanner) Close() {
	s.resultProcessor.Close()
}
