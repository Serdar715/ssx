// ------------------------------------------------------
// Shortscan v2 - Result Processor
// CVSS scoring, deduplication, and multiple output formats
// ------------------------------------------------------

package result

import (
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

	"github.com/bitquark/shortscan/v2/pkg/config"
	"github.com/bitquark/shortscan/v2/pkg/detection"
)

// CVSSScore represents CVSS scoring information
type CVSSScore struct {
	Vector      string  `json:"vector"`
	BaseScore   float64 `json:"base_score"`
	ImpactScore float64 `json:"impact_score"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
}

// VulnerabilityInfo represents comprehensive vulnerability information
type VulnerabilityInfo struct {
	ID              string           `json:"id"`
	CVE             string           `json:"cve,omitempty"`
	Name            string           `json:"name"`
	Description     string           `json:"description"`
	CVSS            CVSSScore        `json:"cvss"`
	FilesExposed    []detection.FileInfo `json:"files_exposed"`
	Directories     []string         `json:"directories,omitempty"`
	Remediation     string           `json:"remediation"`
	References      []string         `json:"references,omitempty"`
	DiscoveredAt    time.Time        `json:"discovered_at"`
	TargetURL       string           `json:"target_url"`
	Confidence      float64          `json:"confidence"`
}

// ScanResult represents the complete scan result
type ScanResult struct {
	TargetURL       string              `json:"target_url"`
	ServerInfo      string              `json:"server_info"`
	Vulnerable      bool                `json:"vulnerable"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities"`
	FilesDiscovered []detection.FileInfo `json:"files_discovered"`
	Statistics      ScanStatistics      `json:"statistics"`
	StartTime       time.Time           `json:"start_time"`
	EndTime         time.Time           `json:"end_time"`
	Duration        time.Duration       `json:"duration"`
}

// ScanStatistics holds scan statistics
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

// ResultProcessor handles result processing and output
type ResultProcessor struct {
	config      *config.ScanConfig
	results     map[string]*ScanResult
	filesMap    map[string]struct{} // For deduplication
	mu          sync.RWMutex
	outputFile  *os.File
	csvWriter   *csv.Writer
}

// NewResultProcessor creates a new result processor
func NewResultProcessor(cfg *config.ScanConfig) *ResultProcessor {
	rp := &ResultProcessor{
		config:   cfg,
		results:  make(map[string]*ScanResult),
		filesMap: make(map[string]struct{}),
	}
	
	// Setup output file if specified
	if cfg.OutputFile != "" {
		file, err := os.Create(cfg.OutputFile)
		if err == nil {
			rp.outputFile = file
			if cfg.Output == config.OutputCSV {
				rp.csvWriter = csv.NewWriter(file)
			}
		}
	}
	
	return rp
}

// AddResult adds a scan result
func (rp *ResultProcessor) AddResult(result *ScanResult) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	
	// Deduplicate files
	dedupedFiles := make([]detection.FileInfo, 0)
	for _, file := range result.FilesDiscovered {
		key := result.TargetURL + file.ShortName
		if _, exists := rp.filesMap[key]; !exists {
			rp.filesMap[key] = struct{}{}
			dedupedFiles = append(dedupedFiles, file)
		}
	}
	result.FilesDiscovered = dedupedFiles
	
	rp.results[result.TargetURL] = result
	
	// Write to output immediately
	rp.writeResult(result)
}

// writeResult writes a result to the configured output
func (rp *ResultProcessor) writeResult(result *ScanResult) {
	switch rp.config.Output {
	case config.OutputJSON:
		rp.writeJSON(result)
	case config.OutputCSV:
		rp.writeCSV(result)
	case config.OutputHTML:
		rp.writeHTML(result)
	case config.OutputMarkdown:
		rp.writeMarkdown(result)
	case config.OutputXML:
		rp.writeXML(result)
	default:
		rp.writeHuman(result)
	}
}

// writeHuman writes human-readable output
func (rp *ResultProcessor) writeHuman(result *ScanResult) {
	fmt.Println("\n════════════════════════════════════════════════════════════════════════════════")
	fmt.Printf("URL: %s\n", result.TargetURL)
	fmt.Printf("Server: %s\n", result.ServerInfo)
	
	if result.Vulnerable {
		fmt.Printf("Vulnerable: \x1b[31;1mYes!\x1b[0m\n")
		
		// Print vulnerabilities
		for _, vuln := range result.Vulnerabilities {
			fmt.Printf("\n  [!] %s (CVSS: %.1f - %s)\n", vuln.Name, vuln.CVSS.BaseScore, vuln.CVSS.Severity)
			fmt.Printf("      %s\n", vuln.Description)
		}
		
		// Print discovered files
		if len(result.FilesDiscovered) > 0 {
			fmt.Println("\n  Discovered Files:")
			for _, file := range result.FilesDiscovered {
				fullName := file.FullName
				if fullName == "" {
					fullName = file.ShortName + "?"
				}
				fmt.Printf("    - \x1b[32m%s\x1b[0m -> \x1b[33m%s\x1b[0m\n", file.ShortName, fullName)
			}
		}
	} else {
		fmt.Printf("Vulnerable: \x1b[34mNo\x1b[0m (or no 8.3 files exist)\n")
	}
	
	fmt.Println("════════════════════════════════════════════════════════════════════════════════")
}

// writeJSON writes JSON output
func (rp *ResultProcessor) writeJSON(result *ScanResult) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return
	}
	
	if rp.outputFile != nil {
		rp.outputFile.Write(data)
		rp.outputFile.Write([]byte("\n"))
	} else {
		fmt.Println(string(data))
	}
}

// writeCSV writes CSV output
func (rp *ResultProcessor) writeCSV(result *ScanResult) {
	if rp.csvWriter == nil {
		return
	}
	
	// Write header if first write
	if len(rp.results) == 1 {
		header := []string{"url", "vulnerable", "server", "file_short", "file_full", "confidence", "discovered_at"}
		rp.csvWriter.Write(header)
	}
	
	// Write rows
	for _, file := range result.FilesDiscovered {
		row := []string{
			result.TargetURL,
			fmt.Sprintf("%v", result.Vulnerable),
			result.ServerInfo,
			file.ShortName,
			file.FullName,
			fmt.Sprintf("%.2f", file.Confidence),
			file.DiscoveryTime.Format(time.RFC3339),
		}
		rp.csvWriter.Write(row)
	}
	rp.csvWriter.Flush()
}

// writeHTML writes HTML output
func (rp *ResultProcessor) writeHTML(result *ScanResult) {
	tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>Shortscan v2 - Scan Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }
        .vulnerable { color: #ff6b6b; }
        .safe { color: #4ecdc4; }
        .file { color: #ffd93d; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #333; padding: 10px; text-align: left; }
        th { background: #16213e; }
        .high { background: #ff6b6b; color: #000; }
        .medium { background: #ffd93d; color: #000; }
        .low { background: #4ecdc4; color: #000; }
    </style>
</head>
<body>
    <h1>🌀 Shortscan v2 - Scan Results</h1>
    <div class="target">
        <h2>Target: {{.TargetURL}}</h2>
        <p>Server: {{.ServerInfo}}</p>
        <p>Vulnerable: {{if .Vulnerable}}<span class="vulnerable">YES</span>{{else}}<span class="safe">NO</span>{{end}}</p>
    </div>
    {{if .Vulnerable}}
    <div class="files">
        <h3>Discovered Files ({{len .FilesDiscovered}})</h3>
        <table>
            <tr><th>Short Name</th><th>Full Name</th><th>Confidence</th></tr>
            {{range .FilesDiscovered}}
            <tr>
                <td class="file">{{.ShortName}}</td>
                <td>{{.FullName}}</td>
                <td>{{printf "%.2f" .Confidence}}</td>
            </tr>
            {{end}}
        </table>
    </div>
    {{end}}
    <div class="stats">
        <h3>Statistics</h3>
        <p>Duration: {{.Duration}}</p>
        <p>Requests: {{.Statistics.TotalRequests}}</p>
    </div>
</body>
</html>`
	
	t, err := template.New("html").Parse(tmpl)
	if err != nil {
		return
	}
	
	var output *os.File = os.Stdout
	if rp.outputFile != nil {
		output = rp.outputFile
	}
	
	t.Execute(output, result)
}

// writeMarkdown writes Markdown output
func (rp *ResultProcessor) writeMarkdown(result *ScanResult) {
	var sb strings.Builder
	
	sb.WriteString("# Shortscan v2 - Scan Results\n\n")
	sb.WriteString(fmt.Sprintf("## Target: %s\n\n", result.TargetURL))
	sb.WriteString(fmt.Sprintf("- **Server**: %s\n", result.ServerInfo))
	sb.WriteString(fmt.Sprintf("- **Vulnerable**: %v\n", result.Vulnerable))
	
	if result.Vulnerable && len(result.FilesDiscovered) > 0 {
		sb.WriteString("\n### Discovered Files\n\n")
		sb.WriteString("| Short Name | Full Name | Confidence |\n")
		sb.WriteString("|------------|-----------|------------|\n")
		for _, file := range result.FilesDiscovered {
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %.2f |\n", file.ShortName, file.FullName, file.Confidence))
		}
	}
	
	sb.WriteString("\n### Statistics\n\n")
	sb.WriteString(fmt.Sprintf("- **Duration**: %v\n", result.Duration))
	sb.WriteString(fmt.Sprintf("- **Total Requests**: %d\n", result.Statistics.TotalRequests))
	
	if rp.outputFile != nil {
		rp.outputFile.WriteString(sb.String())
	} else {
		fmt.Print(sb.String())
	}
}

// writeXML writes XML output
func (rp *ResultProcessor) writeXML(result *ScanResult) {
	type XMLResult struct {
		XMLName     xml.Name `xml:"scan_result"`
		TargetURL   string   `xml:"target_url"`
		ServerInfo  string   `xml:"server_info"`
		Vulnerable  bool     `xml:"vulnerable"`
		Files       []detection.FileInfo `xml:"files>file"`
	}
	
	xmlResult := XMLResult{
		TargetURL:   result.TargetURL,
		ServerInfo:  result.ServerInfo,
		Vulnerable:  result.Vulnerable,
		Files:       result.FilesDiscovered,
	}
	
	data, err := xml.MarshalIndent(xmlResult, "", "  ")
	if err != nil {
		return
	}
	
	if rp.outputFile != nil {
		rp.outputFile.Write(data)
	} else {
		fmt.Println(string(data))
	}
}

// CalculateCVSS calculates CVSS score for IIS short filename enumeration
func CalculateCVSS(filesExposed int, sensitiveFiles bool) CVSSScore {
	// CVSS 3.1 Base Score calculation for IIS Short Filename Enumeration
	// Attack Vector: Network (AV:N)
	// Attack Complexity: Low (AC:L)
	// Privileges Required: None (PR:N)
	// User Interaction: None (UI:N)
	// Scope: Unchanged (S:U)
	// Confidentiality Impact: Low (C:L) - reveals file existence/names
	// Integrity Impact: None (I:N)
	// Availability Impact: None (A:N)
	
	var baseScore float64
	var severity string
	
	if sensitiveFiles && filesExposed > 10 {
		// High impact - many sensitive files exposed
		baseScore = 7.5 // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
		severity = "High"
	} else if sensitiveFiles || filesExposed > 5 {
		// Medium impact
		baseScore = 5.3 // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
		severity = "Medium"
	} else {
		// Low impact
		baseScore = 3.7 // Limited exposure
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

// GetResults returns all results
func (rp *ResultProcessor) GetResults() map[string]*ScanResult {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.results
}

// GetSummary returns a summary of all results
func (rp *ResultProcessor) GetSummary() string {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	
	var vulnerable, safe int
	totalFiles := 0
	
	for _, result := range rp.results {
		if result.Vulnerable {
			vulnerable++
			totalFiles += len(result.FilesDiscovered)
		} else {
			safe++
		}
	}
	
	return fmt.Sprintf(
		"Scan Summary: %d targets scanned, %d vulnerable, %d safe, %d files discovered",
		len(rp.results), vulnerable, safe, totalFiles,
	)
}

// Close closes the result processor
func (rp *ResultProcessor) Close() {
	if rp.csvWriter != nil {
		rp.csvWriter.Flush()
	}
	if rp.outputFile != nil {
		rp.outputFile.Close()
	}
}

// SortFilesByConfidence sorts files by confidence level
func SortFilesByConfidence(files []detection.FileInfo) {
	sort.Slice(files, func(i, j int) bool {
		return files[i].Confidence > files[j].Confidence
	})
}
