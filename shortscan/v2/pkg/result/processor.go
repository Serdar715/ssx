// ------------------------------------------------------
// Shortscan v2 - Result Processor
// CVSS scoring, deduplication, and multiple output formats
// ------------------------------------------------------

package result

import (
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/bitquark/shortscan/v2/pkg/config"
	"github.com/bitquark/shortscan/v2/pkg/detection"
)

//go:embed templates/report.html
var htmlReportTemplate string

// CVSSScore represents CVSS scoring information.
type CVSSScore struct {
	Vector      string  `json:"vector"`
	BaseScore   float64 `json:"base_score"`
	ImpactScore float64 `json:"impact_score"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
}

// VulnerabilityInfo represents comprehensive vulnerability information.
type VulnerabilityInfo struct {
	ID           string               `json:"id"`
	CVE          string               `json:"cve,omitempty"`
	Name         string               `json:"name"`
	Description  string               `json:"description"`
	CVSS         CVSSScore            `json:"cvss"`
	FilesExposed []detection.FileInfo `json:"files_exposed"`
	Directories  []string             `json:"directories,omitempty"`
	Remediation  string               `json:"remediation"`
	References   []string             `json:"references,omitempty"`
	DiscoveredAt time.Time            `json:"discovered_at"`
	TargetURL    string               `json:"target_url"`
	Confidence   float64              `json:"confidence"`
}

// ScanResult represents the complete scan result for a single target.
type ScanResult struct {
	TargetURL       string               `json:"target_url"`
	ServerInfo      string               `json:"server_info"`
	Vulnerable      bool                 `json:"vulnerable"`
	Vulnerabilities []VulnerabilityInfo  `json:"vulnerabilities"`
	FilesDiscovered []detection.FileInfo `json:"files_discovered"`
	Statistics      ScanStatistics       `json:"statistics"`
	StartTime       time.Time            `json:"start_time"`
	EndTime         time.Time            `json:"end_time"`
	Duration        time.Duration        `json:"duration"`
}

// ScanStatistics holds per-target scan statistics.
type ScanStatistics struct {
	TotalRequests   int64         `json:"total_requests"`
	SuccessRequests int64         `json:"success_requests"`
	FailedRequests  int64         `json:"failed_requests"`
	Retries         int64         `json:"retries"`
	BytesSent       int64         `json:"bytes_sent"`
	BytesReceived   int64         `json:"bytes_received"`
	AvgLatency      time.Duration `json:"avg_latency"`
	MinLatency      time.Duration `json:"min_latency"`
	MaxLatency      time.Duration `json:"max_latency"`
}

// ResultProcessor handles result processing and output.
// It is safe for concurrent use.
type ResultProcessor struct {
	cfg              *config.ScanConfig
	results          map[string]*ScanResult
	filesMap         map[string]struct{} // for deduplication
	mu               sync.RWMutex
	outputFile       *os.File
	csvWriter        *csv.Writer
	csvHeaderWritten bool // ensures the CSV header is written exactly once
	htmlTmpl         *template.Template
}

// NewResultProcessor creates a new ResultProcessor.
// Returns an error if an output file is configured but cannot be created.
func NewResultProcessor(cfg *config.ScanConfig) (*ResultProcessor, error) {
	rp := &ResultProcessor{
		cfg:      cfg,
		results:  make(map[string]*ScanResult),
		filesMap: make(map[string]struct{}),
	}

	if cfg.OutputFile != "" {
		file, err := os.Create(cfg.OutputFile)
		if err != nil {
			return nil, fmt.Errorf("create output file %q: %w", cfg.OutputFile, err)
		}
		rp.outputFile = file

		if cfg.Output == config.OutputCSV {
			rp.csvWriter = csv.NewWriter(file)
		}
	}

	// Pre-parse the HTML template so errors surface early.
	if cfg.Output == config.OutputHTML {
		tmpl, err := template.New("report").Parse(htmlReportTemplate)
		if err != nil {
			return nil, fmt.Errorf("parse HTML report template: %w", err)
		}
		rp.htmlTmpl = tmpl
	}

	return rp, nil
}

// AddResult adds a scan result, deduplicates files, and immediately writes output.
func (rp *ResultProcessor) AddResult(scanResult *ScanResult) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	// Deduplicate discovered files across all calls.
	dedupedFiles := make([]detection.FileInfo, 0, len(scanResult.FilesDiscovered))
	for _, file := range scanResult.FilesDiscovered {
		key := scanResult.TargetURL + file.ShortName
		if _, exists := rp.filesMap[key]; !exists {
			rp.filesMap[key] = struct{}{}
			dedupedFiles = append(dedupedFiles, file)
		}
	}
	scanResult.FilesDiscovered = dedupedFiles

	rp.results[scanResult.TargetURL] = scanResult

	rp.writeResult(scanResult)
}

// writeResult dispatches to the appropriate format writer.
// Must be called with rp.mu held.
func (rp *ResultProcessor) writeResult(scanResult *ScanResult) {
	switch rp.cfg.Output {
	case config.OutputJSON:
		rp.writeJSON(scanResult)
	case config.OutputCSV:
		rp.writeCSV(scanResult)
	case config.OutputHTML:
		rp.writeHTML(scanResult)
	case config.OutputMarkdown:
		rp.writeMarkdown(scanResult)
	case config.OutputXML:
		rp.writeXML(scanResult)
	default:
		rp.writeHuman(scanResult)
	}
}

// writeHuman writes human-readable output with ANSI colours.
func (rp *ResultProcessor) writeHuman(scanResult *ScanResult) {
	fmt.Println("\n════════════════════════════════════════════════════════════════════════════════")
	fmt.Printf("URL: %s\n", scanResult.TargetURL)
	fmt.Printf("Server: %s\n", scanResult.ServerInfo)

	if scanResult.Vulnerable {
		fmt.Printf("Vulnerable: \x1b[31;1mYes!\x1b[0m\n")

		for _, vuln := range scanResult.Vulnerabilities {
			fmt.Printf("\n  [!] %s (CVSS: %.1f - %s)\n", vuln.Name, vuln.CVSS.BaseScore, vuln.CVSS.Severity)
			fmt.Printf("      %s\n", vuln.Description)
		}

		if len(scanResult.FilesDiscovered) > 0 {
			fmt.Println("\n  Discovered Files:")
			for _, file := range scanResult.FilesDiscovered {
				displayName := file.FullName
				if displayName == "" {
					displayName = file.ShortName + "?"
				}
				fmt.Printf("    - \x1b[32m%s\x1b[0m -> \x1b[33m%s\x1b[0m\n", file.ShortName, displayName)
			}
		}
	} else {
		fmt.Printf("Vulnerable: \x1b[34mNo\x1b[0m (or no 8.3 files exist)\n")
	}

	fmt.Println("════════════════════════════════════════════════════════════════════════════════")
}

// writeJSON marshals the result to indented JSON.
func (rp *ResultProcessor) writeJSON(scanResult *ScanResult) {
	data, err := json.MarshalIndent(scanResult, "", "  ")
	if err != nil {
		log.Errorf("JSON marshal failed for %q: %v", scanResult.TargetURL, err)
		return
	}

	out := rp.writer()
	if _, writeErr := fmt.Fprintf(out, "%s\n", data); writeErr != nil {
		log.Errorf("JSON write failed: %v", writeErr)
	}
}

// writeCSV writes one row per discovered file; the header is written exactly once.
func (rp *ResultProcessor) writeCSV(scanResult *ScanResult) {
	if rp.csvWriter == nil {
		return
	}

	if !rp.csvHeaderWritten {
		header := []string{"url", "vulnerable", "server", "file_short", "file_full", "confidence", "discovered_at"}
		if err := rp.csvWriter.Write(header); err != nil {
			log.Errorf("CSV header write failed: %v", err)
			return
		}
		rp.csvHeaderWritten = true
	}

	for _, file := range scanResult.FilesDiscovered {
		row := []string{
			scanResult.TargetURL,
			fmt.Sprintf("%v", scanResult.Vulnerable),
			scanResult.ServerInfo,
			file.ShortName,
			file.FullName,
			fmt.Sprintf("%.2f", file.Confidence),
			file.DiscoveryTime.Format(time.RFC3339),
		}
		if err := rp.csvWriter.Write(row); err != nil {
			log.Errorf("CSV row write failed: %v", err)
		}
	}
	rp.csvWriter.Flush()
}

// writeHTML renders the embedded HTML template.
func (rp *ResultProcessor) writeHTML(scanResult *ScanResult) {
	out := rp.writer()
	if err := rp.htmlTmpl.Execute(out, scanResult); err != nil {
		log.Errorf("HTML template execution failed for %q: %v", scanResult.TargetURL, err)
	}
}

// writeMarkdown writes Markdown-formatted output.
func (rp *ResultProcessor) writeMarkdown(scanResult *ScanResult) {
	var sb strings.Builder

	sb.WriteString("# Shortscan v2 - Scan Results\n\n")
	sb.WriteString(fmt.Sprintf("## Target: %s\n\n", scanResult.TargetURL))
	sb.WriteString(fmt.Sprintf("- **Server**: %s\n", scanResult.ServerInfo))
	sb.WriteString(fmt.Sprintf("- **Vulnerable**: %v\n", scanResult.Vulnerable))

	if scanResult.Vulnerable && len(scanResult.FilesDiscovered) > 0 {
		sb.WriteString("\n### Discovered Files\n\n")
		sb.WriteString("| Short Name | Full Name | Confidence |\n")
		sb.WriteString("|------------|-----------|------------|\n")
		for _, file := range scanResult.FilesDiscovered {
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %.2f |\n", file.ShortName, file.FullName, file.Confidence))
		}
	}

	sb.WriteString("\n### Statistics\n\n")
	sb.WriteString(fmt.Sprintf("- **Duration**: %v\n", scanResult.Duration))
	sb.WriteString(fmt.Sprintf("- **Total Requests**: %d\n", scanResult.Statistics.TotalRequests))

	out := rp.writer()
	if _, err := fmt.Fprint(out, sb.String()); err != nil {
		log.Errorf("Markdown write failed: %v", err)
	}
}

// writeXML marshals the result to indented XML.
func (rp *ResultProcessor) writeXML(scanResult *ScanResult) {
	type xmlResult struct {
		XMLName    xml.Name             `xml:"scan_result"`
		TargetURL  string               `xml:"target_url"`
		ServerInfo string               `xml:"server_info"`
		Vulnerable bool                 `xml:"vulnerable"`
		Files      []detection.FileInfo `xml:"files>file"`
	}

	payload := xmlResult{
		TargetURL:  scanResult.TargetURL,
		ServerInfo: scanResult.ServerInfo,
		Vulnerable: scanResult.Vulnerable,
		Files:      scanResult.FilesDiscovered,
	}

	data, err := xml.MarshalIndent(payload, "", "  ")
	if err != nil {
		log.Errorf("XML marshal failed for %q: %v", scanResult.TargetURL, err)
		return
	}

	out := rp.writer()
	if _, writeErr := fmt.Fprintf(out, "%s\n", data); writeErr != nil {
		log.Errorf("XML write failed: %v", writeErr)
	}
}

// writer returns the configured output destination (file or stdout).
func (rp *ResultProcessor) writer() *os.File {
	if rp.outputFile != nil {
		return rp.outputFile
	}
	return os.Stdout
}

// CalculateCVSS calculates a CVSS 3.1 base score for IIS short filename enumeration.
func CalculateCVSS(filesExposed int, sensitiveFiles bool) CVSSScore {
	var baseScore float64
	var severity string

	switch {
	case sensitiveFiles && filesExposed > 10:
		baseScore = 7.5
		severity = "High"
	case sensitiveFiles || filesExposed > 5:
		baseScore = 5.3
		severity = "Medium"
	default:
		baseScore = 3.7
		severity = "Low"
	}

	return CVSSScore{
		Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		BaseScore:   baseScore,
		ImpactScore: 1.4,
		Severity:    severity,
		Description: "IIS Short Filename Enumeration allows attackers to discover hidden files and directories through the legacy 8.3 filename convention",
	}
}

// GetResults returns a snapshot of all results.
func (rp *ResultProcessor) GetResults() map[string]*ScanResult {
	rp.mu.RLock()
	defer rp.mu.RUnlock()

	snapshot := make(map[string]*ScanResult, len(rp.results))
	for k, v := range rp.results {
		snapshot[k] = v
	}
	return snapshot
}

// GetSummary returns a one-line summary of all scan results.
func (rp *ResultProcessor) GetSummary() string {
	rp.mu.RLock()
	defer rp.mu.RUnlock()

	var vulnerableCount, safeCount, totalFiles int

	for _, res := range rp.results {
		if res.Vulnerable {
			vulnerableCount++
			totalFiles += len(res.FilesDiscovered)
		} else {
			safeCount++
		}
	}

	return fmt.Sprintf(
		"Scan Summary: %d targets scanned, %d vulnerable, %d safe, %d files discovered",
		len(rp.results), vulnerableCount, safeCount, totalFiles,
	)
}

// Close flushes and closes all open output writers.
func (rp *ResultProcessor) Close() {
	if rp.csvWriter != nil {
		rp.csvWriter.Flush()
	}
	if rp.outputFile != nil {
		if err := rp.outputFile.Close(); err != nil {
			log.Errorf("close output file: %v", err)
		}
	}
}

// SortFilesByConfidence sorts a slice of FileInfo by descending confidence.
func SortFilesByConfidence(files []detection.FileInfo) {
	sort.Slice(files, func(i, j int) bool {
		return files[i].Confidence > files[j].Confidence
	})
}
