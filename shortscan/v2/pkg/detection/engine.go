// ------------------------------------------------------
// Shortscan v2 - Multi-Layer Detection Engine
// Method, Status, Distance, Timing, and Fuzzy detection
// ------------------------------------------------------

package detection

import (
	"context"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Serdar715/ssx/shortscan/v2/pkg/config"
	"github.com/Serdar715/ssx/shortscan/v2/pkg/httpengine"
	"github.com/Serdar715/ssx/shortscan/v2/pkg/levenshtein"
)

// DetectionResult represents the result of a vulnerability detection pass.
type DetectionResult struct {
	Vulnerable bool    `json:"vulnerable"`
	Confidence float64 `json:"confidence"`
	// DetectionMode is the algorithm used (e.g. "status", "method").
	DetectionMode string `json:"detection_mode"`
	// Method is the HTTP verb that triggered the match (e.g. "OPTIONS").
	Method string `json:"method"`
	// Suffix is the path suffix used to trigger the response difference (e.g. ".aspx").
	Suffix        string        `json:"suffix"`
	StatusPos     int           `json:"status_pos"`
	StatusNeg     int           `json:"status_neg"`
	Tildes        []string      `json:"tildes"`
	TimingDelta   time.Duration `json:"timing_delta"`
	DistanceDelta float64       `json:"distance_delta"`
}

// FileInfo represents discovered file information.
type FileInfo struct {
	ShortName     string    `json:"short_name"`
	FullName      string    `json:"full_name"`
	Extension     string    `json:"extension"`
	Tilde         string    `json:"tilde"`
	BaseURL       string    `json:"base_url"`
	Confidence    float64   `json:"confidence"`
	DiscoveryTime time.Time `json:"discovery_time"`
	StatusCode    int       `json:"status_code"`
	ContentLength int64     `json:"content_length"`
}

// TimingStats holds timing-based detection statistics.
// All exported methods are safe for concurrent use.
type TimingStats struct {
	samples   []time.Duration
	mean      time.Duration
	stdDev    time.Duration
	threshold time.Duration
	mu        sync.RWMutex
}

// NewTimingStats creates a new TimingStats with pre-allocated sample storage.
func NewTimingStats() *TimingStats {
	return &TimingStats{
		samples: make([]time.Duration, 0, config.TimingSampleWindow),
	}
}

// AddSample appends a timing observation and recalculates statistics.
func (ts *TimingStats) AddSample(duration time.Duration) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.samples = append(ts.samples, duration)
	if len(ts.samples) > config.TimingSampleWindow {
		ts.samples = ts.samples[1:]
	}

	ts.calculateStats()
}

// calculateStats must be called with ts.mu held for writing.
func (ts *TimingStats) calculateStats() {
	if len(ts.samples) == 0 {
		return
	}

	var total time.Duration
	for _, sample := range ts.samples {
		total += sample
	}
	ts.mean = total / time.Duration(len(ts.samples))

	var variance float64
	for _, sample := range ts.samples {
		delta := float64(sample - ts.mean)
		variance += delta * delta
	}
	ts.stdDev = time.Duration(math.Sqrt(variance / float64(len(ts.samples))))
	ts.threshold = ts.mean + ts.stdDev*time.Duration(config.TimingStdDevMultiplier)
}

// IsAnomaly reports whether the given duration is statistically anomalous.
func (ts *TimingStats) IsAnomaly(duration time.Duration) bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if ts.threshold == 0 {
		return false
	}
	return duration > ts.threshold
}

// DistanceResult holds distance calculation results.
type DistanceResult struct {
	Distance float64
	Body     string
}

// HTTP methods for detection (ordered by frequency and likely response time).
var httpMethods = []string{
	"OPTIONS", "HEAD", "TRACE", "DEBUG", "GET", "POST", "PUT", "PATCH", "DELETE", "ACL",
	"BASELINE-CONTROL", "BIND", "CHECKIN", "CHECKOUT", "CONNECT", "COPY", "LABEL", "LINK",
	"LOCK", "MERGE", "MKACTIVITY", "MKCALENDAR", "MKCOL", "MKREDIRECTREF", "MKWORKSPACE",
	"MOVE", "ORDERPATCH", "PRI", "PROPFIND", "PROPPATCH", "REBIND", "REPORT", "SEARCH",
	"UNBIND", "UNCHECKOUT", "UNLINK", "UNLOCK", "UPDATE", "UPDATEREDIRECTREF", "VERSION-CONTROL",
}

// pathSuffixes are URL suffixes tried during detection.
var pathSuffixes = []string{
	"/", "", "/.aspx", "?aspxerrorpath=/", "/.aspx?aspxerrorpath=/", "/.asmx", "/.vb",
}

// DetectionEngine is the main detection engine.
// It is safe for concurrent use; each exported method uses its own synchronisation.
type DetectionEngine struct {
	cfg        *config.ScanConfig
	httpEngine *httpengine.HTTPEngine

	// Detection caches — protected by mu.
	statusCache   map[string]map[int]struct{}
	distanceCache map[string]map[int]DistanceResult
	timingStats   map[string]*TimingStats

	// Regex for checksum detection.
	checksumRegex *regexp.Regexp

	mu sync.RWMutex
}

// NewDetectionEngine creates a new detection engine configured from cfg.
func NewDetectionEngine(cfg *config.ScanConfig, httpEngine *httpengine.HTTPEngine) *DetectionEngine {
	return &DetectionEngine{
		cfg:           cfg,
		httpEngine:    httpEngine,
		statusCache:   make(map[string]map[int]struct{}),
		distanceCache: make(map[string]map[int]DistanceResult),
		timingStats:   make(map[string]*TimingStats),
		checksumRegex: regexp.MustCompile(`.{1,2}[0-9A-F]{4}`),
	}
}

// DetectVulnerability performs vulnerability detection against baseURL.
func (de *DetectionEngine) DetectVulnerability(ctx context.Context, baseURL string) (*DetectionResult, error) {
	result := &DetectionResult{
		Vulnerable: false,
		Confidence: 0.0,
		Tildes:     make([]string, 0),
	}

	baseURL = strings.TrimSuffix(baseURL, "/") + "/"

	mode := de.cfg.DetectionMode
	if mode == config.DetectionAuto {
		mode = de.autoSelectMode(ctx, baseURL)
	}
	result.DetectionMode = string(mode)

	// Determine patience level: higher patience → more path/method combinations.
	pathCount := 4
	methodCount := 9
	if de.cfg.Patience == 1 {
		pathCount = len(pathSuffixes)
		methodCount = len(httpMethods)
	}

outerLoop:
	for _, suffix := range pathSuffixes[:pathCount] {
		for _, method := range httpMethods[:methodCount] {
			statusNeg, err := de.getNegativeStatus(ctx, baseURL, method, suffix)
			if err != nil {
				continue
			}

			for tildeIdx := 1; tildeIdx <= config.MaxTildeIndex; tildeIdx++ {
				statusPos, matched := de.checkTildeFile(ctx, baseURL, method, suffix, tildeIdx, statusNeg)
				if !matched {
					continue
				}

				tildeName := fmt.Sprintf("~%d", tildeIdx)
				result.Vulnerable = true
				result.Tildes = append(result.Tildes, tildeName)
				result.StatusPos = statusPos
				result.StatusNeg = statusNeg
				result.Confidence = 0.9
				// Store the actual HTTP verb that worked so enumeration
				// can reuse it instead of using the detection mode name.
				result.Method = method
				// Store the suffix so enumeration uses the same URL shape
				// that triggered the detectable status difference.
				result.Suffix = suffix

				if de.cfg.VulnCheckOnly {
					break outerLoop
				}
			}

			if result.Vulnerable {
				break outerLoop
			}
		}
	}

	// Timing detection as a supplementary signal.
	if de.cfg.EnableTiming && result.Confidence < 0.8 {
		timingConfidence := de.timingDetection(ctx, baseURL)
		if timingConfidence > result.Confidence {
			result.Confidence = timingConfidence
		}
	}

	return result, nil
}

// autoSelectMode selects the most appropriate detection mode by probing the server.
func (de *DetectionEngine) autoSelectMode(ctx context.Context, baseURL string) config.DetectionMode {
	resp, err := de.httpEngine.Request(ctx, "_", baseURL, nil)
	if err == nil {
		defer drainAndClose(resp.Body)
		if resp.StatusCode == 405 {
			return config.DetectionMethod
		}
	}
	return config.DetectionStatus
}

// getNegativeStatus establishes the expected HTTP status code for non-existent tilde files.
// Returns an error if the server's responses are inconsistent or if no response was received.
func (de *DetectionEngine) getNegativeStatus(ctx context.Context, baseURL, method, suffix string) (int, error) {
	var lastStatus int
	anyResponse := false

	for idx := 0; idx < config.NegativeCheckCount; idx++ {
		// Use tildes >= NegativeTildeOffset, which cannot exist on Windows 2000+.
		testURL := fmt.Sprintf("%s*~%d*%s", baseURL, config.NegativeTildeOffset+idx, suffix)

		resp, err := de.httpEngine.Request(ctx, method, testURL, nil)
		if err != nil {
			continue
		}
		drainAndClose(resp.Body)

		status := resp.StatusCode
		if anyResponse && status != lastStatus {
			return 0, fmt.Errorf("inconsistent negative status codes: got %d then %d", lastStatus, status)
		}

		lastStatus = status
		anyResponse = true
	}

	if !anyResponse {
		return 0, fmt.Errorf("no response received for negative check on %q", baseURL)
	}

	return lastStatus, nil
}

// checkTildeFile checks whether a specific tilde variant exists.
func (de *DetectionEngine) checkTildeFile(ctx context.Context, baseURL, method, suffix string, tildeIdx, statusNeg int) (int, bool) {
	testURL := fmt.Sprintf("%s*~%d*%s", baseURL, tildeIdx, suffix)

	resp, err := de.httpEngine.Request(ctx, method, testURL, nil)
	if err != nil {
		return 0, false
	}
	drainAndClose(resp.Body)

	statusPos := resp.StatusCode
	if statusPos == statusNeg {
		return 0, false
	}

	// Verify against a guaranteed-negative probe to avoid coincidental status differences.
	negURL := fmt.Sprintf("%s*~0*%s", baseURL, suffix)
	negResp, negErr := de.httpEngine.Request(ctx, method, negURL, nil)
	if negErr != nil {
		return 0, false
	}
	drainAndClose(negResp.Body)

	if statusPos != negResp.StatusCode {
		return statusPos, true
	}

	return 0, false
}

// timingDetection performs timing-based anomaly detection.
func (de *DetectionEngine) timingDetection(ctx context.Context, baseURL string) float64 {
	stats := NewTimingStats()

	// Collect baseline timings using guaranteed non-existent tilde indices.
	for idx := 0; idx < config.TimingBaselines; idx++ {
		testURL := fmt.Sprintf("%s*~%d*", baseURL, config.NegativeTildeOffset+config.MaxTildeIndex+idx)
		start := time.Now()
		resp, err := de.httpEngine.Request(ctx, "GET", testURL, nil)
		if err == nil {
			drainAndClose(resp.Body)
		}
		stats.AddSample(time.Since(start))
	}

	// Compare potential-match timings against the baseline.
	for tildeIdx := 1; tildeIdx <= config.MaxTildeIndex; tildeIdx++ {
		testURL := fmt.Sprintf("%s*~%d*", baseURL, tildeIdx)
		start := time.Now()
		resp, err := de.httpEngine.Request(ctx, "GET", testURL, nil)
		if err == nil {
			drainAndClose(resp.Body)
		}
		if stats.IsAnomaly(time.Since(start)) {
			return 0.7
		}
	}

	return 0.0
}

// charResult carries a single character discovery outcome for concurrent character discovery.
type charResult struct {
	tilde string
	char  rune
	found bool
}

// discoverCharacters discovers which characters from chars are used in file names or extensions.
// Each character is probed concurrently to reduce total wall-clock time.
func (de *DetectionEngine) discoverCharacters(
	ctx context.Context,
	baseURL string,
	chars string,
	detResult *DetectionResult,
	isFileName bool,
) map[string]string {
	runes := []rune(chars)
	results := make(chan charResult, len(detResult.Tildes)*len(runes))

	var wg sync.WaitGroup

	for _, tilde := range detResult.Tildes {
		for _, char := range runes {
			wg.Add(1)
			go func(tildeVal string, charVal rune) {
				defer wg.Done()

				var testURL string
				if isFileName {
					// Does any file starting with charVal match tildeVal?
					// Use the same URL suffix that was used during detection.
					testURL = fmt.Sprintf("%s%c*%s*%s", baseURL, charVal, tildeVal, detResult.Suffix)
				} else {
					// Extension discovery: does any ~N file have an ext starting with charVal?
					// Suffix not applicable here; the IIS pattern is *~N.C*
					testURL = fmt.Sprintf("%s*%s.%c*", baseURL, tildeVal, charVal)
				}

				resp, err := de.httpEngine.Request(ctx, detResult.Method, testURL, nil)
				found := false
				if err == nil {
					drainAndClose(resp.Body)
					found = resp.StatusCode != detResult.StatusNeg
				}
				results <- charResult{tilde: tildeVal, char: charVal, found: found}
			}(tilde, char)
		}
	}

	// Close results once all goroutines finish.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Aggregate: preserve character order from the original charset string.
	// Build an ordered set per tilde.
	foundMap := make(map[string]map[rune]struct{})
	for _, tilde := range detResult.Tildes {
		foundMap[tilde] = make(map[rune]struct{})
	}

	for res := range results {
		if res.found {
			foundMap[res.tilde][res.char] = struct{}{}
		}
	}

	charMap := make(map[string]string, len(detResult.Tildes))
	for _, tilde := range detResult.Tildes {
		var builder strings.Builder
		for _, char := range runes { // preserve original charset order
			if _, exists := foundMap[tilde][char]; exists {
				builder.WriteRune(char)
			}
		}
		charMap[tilde] = builder.String()
	}

	return charMap
}

// EnumerateFiles performs full file/directory enumeration using the detection result.
func (de *DetectionEngine) EnumerateFiles(ctx context.Context, baseURL string, detResult *DetectionResult) ([]FileInfo, error) {
	// Normalise baseURL to always end with '/' so all URL patterns are correct.
	baseURL = strings.TrimSuffix(baseURL, "/") + "/"

	chars := de.cfg.Characters

	fileChars := de.discoverCharacters(ctx, baseURL, chars, detResult, true)
	extChars := de.discoverCharacters(ctx, baseURL, chars, detResult, false)

	allFiles := make([]FileInfo, 0)
	for _, tilde := range detResult.Tildes {
		discovered := de.enumerateRecursive(ctx, baseURL, "", tilde, "", fileChars[tilde], extChars[tilde], detResult)
		allFiles = append(allFiles, discovered...)
	}

	return allFiles, nil
}

// enumerateFileName recursively builds the 8.3 filename prefix (up to MaxFilenameLen chars).
// When no further char extends the prefix, it calls enumerateExtension to discover the extension.
func (de *DetectionEngine) enumerateFileName(
	ctx context.Context,
	baseURL, file, tilde, fileChars, extChars string,
	detResult *DetectionResult,
) []FileInfo {
	files := make([]FileInfo, 0)
	anyMatch := false

	for _, char := range []rune(fileChars) {
		newFile := file + string(char)
		// IIS pattern: NEWFILE*~N*SUFFIX — does any file starting with newFile exist?
		testURL := fmt.Sprintf("%s%s*%s*%s", baseURL, newFile, tilde, detResult.Suffix)

		resp, err := de.httpEngine.Request(ctx, detResult.Method, testURL, nil)
		if err != nil {
			continue
		}
		drainAndClose(resp.Body)
		// Exact match: only the same statusPos seen during detection counts as a hit.
		// Checking != statusNeg causes false-positives → runaway recursion → very slow scan.
		if resp.StatusCode != detResult.StatusPos {
			continue
		}

		anyMatch = true

		if len(newFile) < config.MaxFilenameLen {
			// Recurse: try to extend filename by one more char.
			deeper := de.enumerateFileName(ctx, baseURL, newFile, tilde, fileChars, extChars, detResult)
			if len(deeper) > 0 {
				files = append(files, deeper...)
			} else {
				// No char extends newFile further → filename is complete at newFile.
				files = append(files, de.enumerateExtension(ctx, baseURL, newFile, tilde, "", extChars, detResult)...)
			}
		} else {
			// Reached MaxFilenameLen — must transition to extension discovery.
			files = append(files, de.enumerateExtension(ctx, baseURL, newFile, tilde, "", extChars, detResult)...)
		}
	}

	// If nothing matched and we already have a non-empty prefix,
	// the filename ends here; try extension discovery.
	if !anyMatch && len(file) > 0 {
		files = append(files, de.enumerateExtension(ctx, baseURL, file, tilde, "", extChars, detResult)...)
	}

	return files
}

// enumerateExtension recursively builds the 8.3 extension (up to MaxExtensionLen chars).
// If no extension chars match, the file is recorded without an extension.
func (de *DetectionEngine) enumerateExtension(
	ctx context.Context,
	baseURL, file, tilde, ext, extChars string,
	detResult *DetectionResult,
) []FileInfo {
	files := make([]FileInfo, 0)
	anyMatch := false

	for _, char := range []rune(extChars) {
		newExt := ext + string(char)
		// IIS pattern: FILE~N.EXT* — does the file have an extension starting with newExt?
		testURL := fmt.Sprintf("%s%s%s.%s*", baseURL, file, tilde, newExt)

		resp, err := de.httpEngine.Request(ctx, detResult.Method, testURL, nil)
		if err != nil {
			continue
		}
		drainAndClose(resp.Body)
		if resp.StatusCode != detResult.StatusPos {
			continue
		}

		anyMatch = true

		if len(newExt) < config.MaxExtensionLen {
			deeper := de.enumerateExtension(ctx, baseURL, file, tilde, newExt, extChars, detResult)
			if len(deeper) > 0 {
				files = append(files, deeper...)
			} else {
				// No char extends ext further → extension complete at newExt.
				files = append(files, de.makeFileInfo(baseURL, file, tilde, "."+newExt))
			}
		} else {
			// Reached MaxExtensionLen.
			files = append(files, de.makeFileInfo(baseURL, file, tilde, "."+newExt))
		}
	}

	// Extension enumeration complete (or was called with empty ext meaning "no matches").
	if !anyMatch {
		if len(ext) > 0 {
			// Partial ext that couldn't be extended → record as-is.
			files = append(files, de.makeFileInfo(baseURL, file, tilde, "."+ext))
		} else {
			// No extension at all — record file without extension.
			files = append(files, de.makeFileInfo(baseURL, file, tilde, ""))
		}
	}

	return files
}

// enumerateRecursive is the public entry point kept for API compatibility.
// It dispatches to enumerateFileName (ext=="") or enumerateExtension (ext!="").
func (de *DetectionEngine) enumerateRecursive(
	ctx context.Context,
	baseURL, file, tilde, ext, fileChars, extChars string,
	detResult *DetectionResult,
) []FileInfo {
	if ext != "" {
		return de.enumerateExtension(ctx, baseURL, file, tilde, ext, extChars, detResult)
	}
	return de.enumerateFileName(ctx, baseURL, file, tilde, fileChars, extChars, detResult)
}

// makeFileInfo constructs a FileInfo for a discovered short filename.
func (de *DetectionEngine) makeFileInfo(baseURL, file, tilde, ext string) FileInfo {
	return FileInfo{
		ShortName:     file + tilde + ext,
		BaseURL:       baseURL,
		Tilde:         tilde,
		Extension:     ext,
		DiscoveryTime: time.Now(),
		Confidence:    0.95,
	}
}

// FuzzyMatch returns the similarity score (0.0–1.0) between two response bodies.
func (de *DetectionEngine) FuzzyMatch(body1, body2 string) float64 {
	if len(body1) == 0 || len(body2) == 0 {
		return 0.0
	}

	distance := levenshtein.Distance(body1, body2)
	maxLen := float64(max(len(body1), len(body2)))
	return 1.0 - (float64(distance) / maxLen)
}

// GetNegativeStatuses returns cached negative statuses for an extension (used by callers).
func (de *DetectionEngine) GetNegativeStatuses(ext string) map[int]struct{} {
	de.mu.RLock()
	defer de.mu.RUnlock()
	return de.statusCache[ext]
}

// CacheNegativeStatuses stores negative statuses for an extension.
func (de *DetectionEngine) CacheNegativeStatuses(ext string, statuses map[int]struct{}) {
	de.mu.Lock()
	defer de.mu.Unlock()
	de.statusCache[ext] = statuses
}

// drainAndClose fully reads and closes an HTTP response body to allow connection re-use.
// It is safe to call with a nil body.
func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}
