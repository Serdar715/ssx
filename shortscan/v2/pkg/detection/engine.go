// ------------------------------------------------------
// Shortscan v2 - Multi-Layer Detection Engine
// Method, Status, Distance, Timing, and Fuzzy detection
// ------------------------------------------------------

package detection

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bitquark/shortscan/v2/pkg/config"
	"github.com/bitquark/shortscan/v2/pkg/httpengine"
	"github.com/bitquark/shortscan/v2/pkg/levenshtein"
)

// DetectionResult represents the result of a detection
type DetectionResult struct {
	Vulnerable    bool          `json:"vulnerable"`
	Confidence    float64       `json:"confidence"`
	Method        string        `json:"method"`
	StatusPos     int           `json:"status_pos"`
	StatusNeg     int           `json:"status_neg"`
	Tildes        []string      `json:"tildes"`
	TimingDelta   time.Duration `json:"timing_delta"`
	DistanceDelta float64       `json:"distance_delta"`
}

// FileInfo represents discovered file information
type FileInfo struct {
	ShortName    string    `json:"short_name"`
	FullName     string    `json:"full_name"`
	Extension    string    `json:"extension"`
	Tilde        string    `json:"tilde"`
	BaseURL      string    `json:"base_url"`
	Confidence   float64   `json:"confidence"`
	DiscoveryTime time.Time `json:"discovery_time"`
	StatusCode   int       `json:"status_code"`
	ContentLength int64    `json:"content_length"`
}

// TimingStats holds timing-based detection statistics
type TimingStats struct {
	samples    []time.Duration
	mean       time.Duration
	stdDev     time.Duration
	threshold  time.Duration
	mu         sync.RWMutex
}

// NewTimingStats creates new timing statistics
func NewTimingStats() *TimingStats {
	return &TimingStats{
		samples: make([]time.Duration, 0, 100),
	}
}

// AddSample adds a timing sample
func (ts *TimingStats) AddSample(d time.Duration) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	
	ts.samples = append(ts.samples, d)
	if len(ts.samples) > 100 {
		ts.samples = ts.samples[1:]
	}
	
	ts.calculateStats()
}

// calculateStats calculates mean and standard deviation
func (ts *TimingStats) calculateStats() {
	if len(ts.samples) == 0 {
		return
	}
	
	// Calculate mean
	var total time.Duration
	for _, s := range ts.samples {
		total += s
	}
	ts.mean = total / time.Duration(len(ts.samples))
	
	// Calculate standard deviation
	var variance float64
	for _, s := range ts.samples {
		delta := float64(s - ts.mean)
		variance += delta * delta
	}
	stdDevMs := math.Sqrt(variance / float64(len(ts.samples)))
	ts.stdDev = time.Duration(stdDevMs)
	
	// Set threshold at 2 standard deviations above mean
	ts.threshold = ts.mean + (ts.stdDev * 2)
}

// IsAnomaly checks if a timing is anomalous
func (ts *TimingStats) IsAnomaly(d time.Duration) bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	
	if ts.threshold == 0 {
		return false
	}
	
	return d > ts.threshold
}

// DetectionEngine is the main detection engine
type DetectionEngine struct {
	config      *config.ScanConfig
	httpEngine  *httpengine.HTTPEngine
	
	// Detection caches
	statusCache   map[string]map[int]struct{}
	distanceCache map[string]map[int]DistanceResult
	timingStats   map[string]*TimingStats
	
	// Regex for checksum detection
	checksumRegex *regexp.Regexp
	
	mu sync.RWMutex
}

// DistanceResult holds distance calculation results
type DistanceResult struct {
	Distance float64
	Body     string
}

// HTTP methods for detection (ordered by frequency and probable response time)
var httpMethods = []string{
	"OPTIONS", "HEAD", "TRACE", "DEBUG", "GET", "POST", "PUT", "PATCH", "DELETE", "ACL",
	"BASELINE-CONTROL", "BIND", "CHECKIN", "CHECKOUT", "CONNECT", "COPY", "LABEL", "LINK",
	"LOCK", "MERGE", "MKACTIVITY", "MKCALENDAR", "MKCOL", "MKREDIRECTREF", "MKWORKSPACE",
	"MOVE", "ORDERPATCH", "PRI", "PROPFIND", "PROPPATCH", "REBIND", "REPORT", "SEARCH",
	"UNBIND", "UNCHECKOUT", "UNLINK", "UNLOCK", "UPDATE", "UPDATEREDIRECTREF", "VERSION-CONTROL",
}

// Path suffixes to try
var pathSuffixes = []string{
	"/", "", "/.aspx", "?aspxerrorpath=/", "/.aspx?aspxerrorpath=/", "/.asmx", "/.vb",
}

// NewDetectionEngine creates a new detection engine
func NewDetectionEngine(cfg *config.ScanConfig, httpEngine *httpengine.HTTPEngine) *DetectionEngine {
	return &DetectionEngine{
		config:        cfg,
		httpEngine:    httpEngine,
		statusCache:   make(map[string]map[int]struct{}),
		distanceCache: make(map[string]map[int]DistanceResult),
		timingStats:   make(map[string]*TimingStats),
		checksumRegex: regexp.MustCompile(".{1,2}[0-9A-F]{4}"),
	}
}

// DetectVulnerability performs vulnerability detection
func (de *DetectionEngine) DetectVulnerability(ctx context.Context, baseURL string) (*DetectionResult, error) {
	result := &DetectionResult{
		Vulnerable: false,
		Confidence: 0.0,
		Tildes:     make([]string, 0),
	}
	
	// Normalize URL
	baseURL = strings.TrimSuffix(baseURL, "/") + "/"
	
	// Determine detection method
	mode := de.config.DetectionMode
	if mode == config.DetectionAuto {
		mode = de.autoSelectMode(ctx, baseURL)
	}
	
	result.Method = string(mode)
	
	// Determine patience level
	var pc, mc int
	if de.config.Patience == 1 {
		pc = len(pathSuffixes)
		mc = len(httpMethods)
	} else {
		pc = 4
		mc = 9
	}
	
	// Try different path suffixes and methods
outerLoop:
	for _, suffix := range pathSuffixes[:pc] {
		for _, method := range httpMethods[:mc] {
			// Get negative status code (non-existent file)
			statusNeg, err := de.getNegativeStatus(ctx, baseURL, method, suffix)
			if err != nil {
				continue
			}
			
			// Check for tilde files (~1 through ~4)
			for i := 1; i <= 4; i++ {
				statusPos, hasMatch := de.checkTildeFile(ctx, baseURL, method, suffix, i, statusNeg)
				if hasMatch {
					result.Vulnerable = true
					result.Tildes = append(result.Tildes, fmt.Sprintf("~%d", i))
					result.StatusPos = statusPos
					result.StatusNeg = statusNeg
					result.Confidence = 0.9
					
					// Break if only checking vulnerability
					if de.config.VulnCheckOnly {
						break outerLoop
					}
				}
			}
			
			if result.Vulnerable {
				break outerLoop
			}
		}
	}
	
	// Timing-based detection as additional check
	if de.config.EnableTiming && result.Confidence < 0.8 {
		timingConfidence := de.timingDetection(ctx, baseURL)
		if timingConfidence > result.Confidence {
			result.Confidence = timingConfidence
		}
	}
	
	return result, nil
}

// autoSelectMode automatically selects the best detection mode
func (de *DetectionEngine) autoSelectMode(ctx context.Context, baseURL string) config.DetectionMode {
	// Check if method-based detection works (405 Method Not Allowed)
	resp, err := de.httpEngine.Request(ctx, "_", baseURL, nil)
	if err == nil && resp.StatusCode == 405 {
		return config.DetectionMethod
	}
	
	// Default to status-based detection
	return config.DetectionStatus
}

// getNegativeStatus gets the status code for non-existent files
func (de *DetectionEngine) getNegativeStatus(ctx context.Context, baseURL, method, suffix string) (int, error) {
	var lastStatus int
	
	for i := 0; i < 4; i++ {
		// Use tilde >= ~5 which will never exist on Windows 2000+
		testURL := fmt.Sprintf("%s*~%d*%s", baseURL, 5+i, suffix)
		
		resp, err := de.httpEngine.Request(ctx, method, testURL, nil)
		if err != nil {
			continue
		}
		
		status := resp.StatusCode
		
		// Check for consistency
		if lastStatus != 0 && status != lastStatus {
			return 0, fmt.Errorf("inconsistent status codes")
		}
		
		lastStatus = status
	}
	
	return lastStatus, nil
}

// checkTildeFile checks for existence of a specific tilde file
func (de *DetectionEngine) checkTildeFile(ctx context.Context, baseURL, method, suffix string, tilde int, statusNeg int) (int, bool) {
	testURL := fmt.Sprintf("%s*~%d*%s", baseURL, tilde, suffix)
	
	resp, err := de.httpEngine.Request(ctx, method, testURL, nil)
	if err != nil {
		return 0, false
	}
	
	statusPos := resp.StatusCode
	
	// Check if this looks like a hit
	if statusPos != statusNeg {
		// Verify with negative check
		negURL := fmt.Sprintf("%s*~0*%s", baseURL, suffix)
		negResp, err := de.httpEngine.Request(ctx, method, negURL, nil)
		if err == nil && statusPos != negResp.StatusCode {
			return statusPos, true
		}
	}
	
	return 0, false
}

// timingDetection performs timing-based detection
func (de *DetectionEngine) timingDetection(ctx context.Context, baseURL string) float64 {
	stats := NewTimingStats()
	
	// Collect baseline timing for non-existent files
	for i := 0; i < 10; i++ {
		testURL := fmt.Sprintf("%s*~%d*", baseURL, 10+i)
		start := time.Now()
		_, _ = de.httpEngine.Request(ctx, "GET", testURL, nil)
		stats.AddSample(time.Since(start))
	}
	
	// Check timing for potential matches
	for i := 1; i <= 4; i++ {
		testURL := fmt.Sprintf("%s*~%d*", baseURL, i)
		start := time.Now()
		_, _ = de.httpEngine.Request(ctx, "GET", testURL, nil)
		latency := time.Since(start)
		
		if stats.IsAnomaly(latency) {
			return 0.7 // High confidence from timing
		}
	}
	
	return 0.0
}

// EnumerateFiles performs file enumeration
func (de *DetectionEngine) EnumerateFiles(ctx context.Context, baseURL string, result *DetectionResult) ([]FileInfo, error) {
	files := make([]FileInfo, 0)
	
	// Determine characters to use
	chars := de.config.Characters
	
	// Discover which characters are in use
	fileChars := de.discoverCharacters(ctx, baseURL, chars, result, true)
	extChars := de.discoverCharacters(ctx, baseURL, chars, result, false)
	
	// Enumerate files for each tilde
	for _, tilde := range result.Tildes {
		discovered := de.enumerateRecursive(ctx, baseURL, "", tilde, "", fileChars[tilde], extChars[tilde], result)
		files = append(files, discovered...)
	}
	
	return files, nil
}

// discoverCharacters discovers which characters are in use
func (de *DetectionEngine) discoverCharacters(ctx context.Context, baseURL, chars string, result *DetectionResult, isFile bool) map[string]string {
	charMap := make(map[string]string)
	
	for _, tilde := range result.Tildes {
		var foundChars string
		
		for _, char := range chars {
			var testURL string
			if isFile {
				testURL = fmt.Sprintf("%s*%c*%s*", baseURL, char, tilde)
			} else {
				testURL = fmt.Sprintf("%s*%s*%c*", baseURL, tilde, char)
			}
			
			resp, err := de.httpEngine.Request(ctx, result.Method, testURL, nil)
			if err == nil && resp.StatusCode != result.StatusNeg {
				foundChars += string(char)
			}
		}
		
		charMap[tilde] = foundChars
	}
	
	return charMap
}

// enumerateRecursive performs recursive enumeration
func (de *DetectionEngine) enumerateRecursive(ctx context.Context, baseURL, file, tilde, ext, fileChars, extChars string, result *DetectionResult) []FileInfo {
	files := make([]FileInfo, 0)
	
	// Determine if we're enumerating file or extension
	extMode := len(ext) > 0
	chars := fileChars
	if extMode {
		chars = extChars
	}
	
	for _, char := range chars {
		var newFile, newExt string
		if extMode {
			newExt = ext + string(char)
		} else {
			newFile = file + string(char)
		}
		
		// Check if this character sequence exists
		var testURL string
		if extMode {
			testURL = fmt.Sprintf("%s%s%s%s*%s", baseURL, newFile, tilde, newExt, result.Method)
		} else {
			testURL = fmt.Sprintf("%s%s*%s*%s", baseURL, newFile, tilde, newExt, result.Method)
		}
		
		resp, err := de.httpEngine.Request(ctx, result.Method, testURL, nil)
		if err != nil || resp.StatusCode != result.StatusPos {
			continue
		}
		
		// Check for complete file
		if de.isCompleteFile(ctx, baseURL, newFile, tilde, newExt, result) {
			fileInfo := FileInfo{
				ShortName:     newFile + tilde + newExt,
				BaseURL:       baseURL,
				Tilde:         tilde,
				Extension:     newExt,
				DiscoveryTime: time.Now(),
				Confidence:    0.95,
			}
			
			files = append(files, fileInfo)
			continue
		}
		
		// Continue recursion if not complete
		if (!extMode && len(newFile) < 6) || (extMode && len(newExt) < 4) {
			moreFiles := de.enumerateRecursive(ctx, baseURL, newFile, tilde, newExt, fileChars, extChars, result)
			files = append(files, moreFiles...)
		}
	}
	
	return files
}

// isCompleteFile checks if we have a complete file match
func (de *DetectionEngine) isCompleteFile(ctx context.Context, baseURL, file, tilde, ext string, result *DetectionResult) bool {
	// Check for complete file (no wildcards)
	testURL := fmt.Sprintf("%s%s%s%s", baseURL, file, tilde, ext)
	resp, err := de.httpEngine.Request(ctx, result.Method, testURL, nil)
	if err == nil && resp.StatusCode != result.StatusNeg {
		return true
	}
	return false
}

// FuzzyMatch performs fuzzy matching for filename discovery
func (de *DetectionEngine) FuzzyMatch(body1, body2 string) float64 {
	if len(body1) == 0 || len(body2) == 0 {
		return 0.0
	}
	
	// Calculate Levenshtein distance
	distance := levenshtein.Distance(body1, body2)
	maxLen := float64(max(len(body1), len(body2)))
	
	return 1.0 - (float64(distance) / maxLen)
}

// GetNegativeStatuses returns cached negative statuses for an extension
func (de *DetectionEngine) GetNegativeStatuses(ext string) map[int]struct{} {
	de.mu.RLock()
	defer de.mu.RUnlock()
	return de.statusCache[ext]
}

// CacheNegativeStatuses caches negative statuses for an extension
func (de *DetectionEngine) CacheNegativeStatuses(ext string, statuses map[int]struct{}) {
	de.mu.Lock()
	defer de.mu.Unlock()
	de.statusCache[ext] = statuses
}

// Helper functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
