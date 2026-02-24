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
	"sync/atomic"
	"time"

	"github.com/fatih/color"

	"github.com/Serdar715/ssx/shortscan/v2/pkg/config"
	"github.com/Serdar715/ssx/shortscan/v2/pkg/detection"
	"github.com/Serdar715/ssx/shortscan/v2/pkg/httpengine"
	"github.com/Serdar715/ssx/shortscan/v2/pkg/result"
)

// Scanner is the main scanner orchestrator.
type Scanner struct {
	cfg             *config.ScanConfig
	httpEngine      *httpengine.HTTPEngine
	detectionEngine *detection.DetectionEngine
	resultProcessor *result.ResultProcessor

	// Progress tracking — updated atomically.
	totalTargets   int
	scannedTargets atomic.Int32

	// stopped is set to true when the context is cancelled so that
	// in-flight goroutines do not emit results after a Ctrl+C.
	stopped atomic.Bool
}

// NewScanner creates a new Scanner from cfg.
// Returns an error if the result processor cannot initialise its output file.
func NewScanner(cfg *config.ScanConfig) (*Scanner, error) {
	httpEngine := httpengine.NewHTTPEngine(cfg)
	detectionEngine := detection.NewDetectionEngine(cfg, httpEngine)

	resultProcessor, err := result.NewResultProcessor(cfg)
	if err != nil {
		return nil, fmt.Errorf("initialise result processor: %w", err)
	}

	return &Scanner{
		cfg:             cfg,
		httpEngine:      httpEngine,
		detectionEngine: detectionEngine,
		resultProcessor: resultProcessor,
	}, nil
}

// Scan starts the scanning process for the given URL list.
// It respects ctx cancellation: when ctx is cancelled in-flight goroutines exit cleanly.
func (s *Scanner) Scan(ctx context.Context, urls []string) error {
	targets := s.prepareURLs(urls)
	s.totalTargets = len(targets)

	s.printBanner()

	sem := make(chan struct{}, s.cfg.Concurrency)
	var wg sync.WaitGroup

	for _, target := range targets {
		wg.Add(1)

		go func(targetURL string) {
			defer wg.Done()

			// Acquire semaphore — respect context cancellation while waiting.
			select {
			case sem <- struct{}{}:
				// slot acquired
			case <-ctx.Done():
				s.stopped.Store(true)
				return
			}
			defer func() { <-sem }()

			s.scanTarget(ctx, targetURL)
		}(target)
	}

	// Mark stopped before waiting so any goroutine finishing after
	// cancellation also suppresses output.
	go func() {
		<-ctx.Done()
		s.stopped.Store(true)
	}()

	wg.Wait()
	s.printSummary()
	return nil
}

// prepareURLs normalises and deduplicates a list of raw URLs.
func (s *Scanner) prepareURLs(rawURLs []string) []string {
	seen := make(map[string]struct{}, len(rawURLs))
	prepared := make([]string, 0, len(rawURLs))

	for _, rawURL := range rawURLs {
		rawURL = strings.TrimSpace(rawURL)
		if rawURL == "" {
			continue
		}

		if !strings.Contains(rawURL, "://") {
			rawURL = "https://" + rawURL
		}

		rawURL = strings.TrimSuffix(rawURL, "/")

		if _, exists := seen[rawURL]; !exists {
			seen[rawURL] = struct{}{}
			prepared = append(prepared, rawURL)
		}
	}

	return prepared
}

// scanTarget scans a single target URL and stores the result.
// It returns immediately without emitting output if the context was cancelled.
func (s *Scanner) scanTarget(ctx context.Context, targetURL string) {
	// If the caller cancelled before we even started, skip silently.
	if s.stopped.Load() {
		return
	}

	startTime := time.Now()

	scanResult := &result.ScanResult{
		TargetURL:       targetURL,
		Vulnerable:      false,
		StartTime:       startTime,
		FilesDiscovered: make([]detection.FileInfo, 0),
		Vulnerabilities: make([]result.VulnerabilityInfo, 0),
	}

	// Skip the extra HEAD request for server info in vuln-check-only mode.
	if !s.cfg.VulnCheckOnly {
		scanResult.ServerInfo = s.getServerInfo(ctx, targetURL)
	}

	detectionResult, err := s.detectionEngine.DetectVulnerability(ctx, targetURL)
	if err != nil {
		// Don't emit results for errors that stemmed from cancellation.
		if s.stopped.Load() {
			return
		}
		scanResult.EndTime = time.Now()
		scanResult.Duration = scanResult.EndTime.Sub(startTime)
		s.resultProcessor.AddResult(scanResult)
		s.scannedTargets.Add(1)
		return
	}

	scanResult.Vulnerable = detectionResult.Vulnerable

	if detectionResult.Vulnerable {
		vulnInfo := result.VulnerabilityInfo{
			ID:          "IIS-SHORTNAME-001",
			CVE:         "CVE-2025-46294",
			Name:        "IIS Short Filename Enumeration",
			Description: "The target is vulnerable to IIS short filename enumeration, allowing discovery of hidden files and directories",
			Remediation: "Disable 8.3 filename creation by setting NtfsDisable8dot3NameCreation to 1 in the registry",
			References: []string{
				"https://techcommunity.microsoft.com/t5/iis-support-blog/iis-short-name-enumeration/ba-p/3951320",
				"https://nvd.nist.gov/vuln/detail/CVE-2025-46294",
			},
			DiscoveredAt: time.Now(),
			TargetURL:    targetURL,
			Confidence:   detectionResult.Confidence,
		}

		// Set initial CVSS before enumeration (no files yet).
		vulnInfo.CVSS = result.CalculateCVSS(0, false)
		scanResult.Vulnerabilities = append(scanResult.Vulnerabilities, vulnInfo)

		if !s.cfg.VulnCheckOnly {
			files, enumErr := s.detectionEngine.EnumerateFiles(ctx, targetURL, detectionResult)
			if enumErr == nil {
				scanResult.FilesDiscovered = files

				// Update the vulnerability entry in place — avoid stale copy.
				lastIdx := len(scanResult.Vulnerabilities) - 1
				scanResult.Vulnerabilities[lastIdx].FilesExposed = files
				scanResult.Vulnerabilities[lastIdx].CVSS = result.CalculateCVSS(
					len(files),
					s.hasSensitiveFiles(files),
				)
			}
		}
	}

	scanResult.EndTime = time.Now()
	scanResult.Duration = scanResult.EndTime.Sub(startTime)

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

	// Final check: don't print results that arrived after cancellation.
	if s.stopped.Load() {
		return
	}

	s.resultProcessor.AddResult(scanResult)
	s.scannedTargets.Add(1)
}

// getServerInfo retrieves the Server and X-Aspnet-Version headers from the target.
func (s *Scanner) getServerInfo(ctx context.Context, targetURL string) string {
	resp, err := s.httpEngine.Request(ctx, http.MethodGet, targetURL+"/", nil)
	if err != nil {
		return "<unknown>"
	}

	// Drain and close to avoid connection leaks.
	defer func() {
		if resp.Body != nil {
			resp.Body.Close()
		}
	}()

	serverHeader := resp.Header.Get("Server")
	if serverHeader == "" {
		serverHeader = "<unknown>"
	}

	if aspNet := resp.Header.Get("X-Aspnet-Version"); aspNet != "" {
		serverHeader += fmt.Sprintf(" (ASP.NET v%s)", aspNet)
	}

	return serverHeader
}

// sensitivePatterns contains lowercase substrings that indicate a file may be sensitive.
var sensitivePatterns = []string{
	"web.config", "password", "secret", "key", "credential",
	"backup", "database", "admin", "config",
	".bak", ".sql", ".mdb", ".log",
}

// hasSensitiveFiles reports whether any discovered file matches a sensitive pattern.
func (s *Scanner) hasSensitiveFiles(files []detection.FileInfo) bool {
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

// Progress returns the number of targets scanned so far.
func (s *Scanner) Progress() (scanned, total int) {
	return int(s.scannedTargets.Load()), s.totalTargets
}

// printBanner prints the scanner banner unless quiet mode is enabled.
func (s *Scanner) printBanner() {
	if s.cfg.Quiet {
		return
	}

	banner := color.New(color.FgBlue, color.Bold).Sprint("🌀 Shortscan v"+config.Version) +
		" · " + color.New(color.FgWhite, color.Bold).Sprint("Advanced IIS Short Filename Enumeration")

	fmt.Println(banner)
	fmt.Printf("Targets: %d | Concurrency: %d | Timeout: %v\n",
		s.totalTargets, s.cfg.Concurrency, s.cfg.Timeout)
}

// printSummary prints the scan summary unless quiet mode is enabled.
func (s *Scanner) printSummary() {
	if s.cfg.Quiet {
		return
	}

	fmt.Println("\n" + strings.Repeat("═", 80))

	if s.stopped.Load() {
		scanned, total := s.Progress()
		fmt.Printf("Scan interrupted: %d/%d targets scanned\n", scanned, total)
		return
	}

	fmt.Println(s.resultProcessor.GetSummary())

	stats := s.httpEngine.GetStats()
	fmt.Printf("Statistics: %d requests, %d retries, %d bytes sent, %d bytes received\n",
		stats.TotalRequests, stats.Retries, stats.BytesSent, stats.BytesReceived)
}

// Close releases resources held by the scanner.
func (s *Scanner) Close() {
	s.resultProcessor.Close()
}
