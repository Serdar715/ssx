package result_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Serdar715/ssx/shortscan/v2/pkg/config"
	"github.com/Serdar715/ssx/shortscan/v2/pkg/detection"
	"github.com/Serdar715/ssx/shortscan/v2/pkg/result"
)

// newTestResult returns a minimal ScanResult for use in tests.
func newTestResult(targetURL string, vulnerable bool, files []detection.FileInfo) *result.ScanResult {
	return &result.ScanResult{
		TargetURL:       targetURL,
		Vulnerable:      vulnerable,
		ServerInfo:      "Microsoft-IIS/10.0",
		FilesDiscovered: files,
		Vulnerabilities: []result.VulnerabilityInfo{},
	}
}

// TestNewResultProcessorOutputFileError verifies that a bad output path returns an error.
func TestNewResultProcessorOutputFileError(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.OutputFile = "/nonexistent/path/output.json"
	cfg.Output = config.OutputJSON

	_, err := result.NewResultProcessor(cfg)
	if err == nil {
		t.Error("expected error for unwriteable output file, got nil")
	}
}

// TestCSVHeaderWrittenOnce ensures the CSV header appears exactly once across multiple AddResult calls.
func TestCSVHeaderWrittenOnce(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "out.csv")

	cfg := config.DefaultConfig()
	cfg.Output = config.OutputCSV
	cfg.OutputFile = outFile

	rp, err := result.NewResultProcessor(cfg)
	if err != nil {
		t.Fatalf("NewResultProcessor: %v", err)
	}

	files := []detection.FileInfo{
		{ShortName: "ASPNET~1.DLL", FullName: "aspnet_client.dll", Confidence: 0.95},
	}

	rp.AddResult(newTestResult("http://example.com", true, files))
	rp.AddResult(newTestResult("http://example2.com", true, files))
	rp.Close()

	data, readErr := os.ReadFile(outFile)
	if readErr != nil {
		t.Fatalf("read output file: %v", readErr)
	}

	content := string(data)
	headerCount := strings.Count(content, "url,vulnerable,server")
	if headerCount != 1 {
		t.Errorf("CSV header should appear exactly once, found %d times:\n%s", headerCount, content)
	}
}

// TestDeduplicationAcrossResults verifies the same file is not emitted twice.
func TestDeduplicationAcrossResults(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Output = config.OutputHuman // human output goes to stdout, no file needed

	rp, err := result.NewResultProcessor(cfg)
	if err != nil {
		t.Fatalf("NewResultProcessor: %v", err)
	}
	defer rp.Close()

	file := detection.FileInfo{ShortName: "SECRET~1.TXT", FullName: "secret.txt", Confidence: 0.9}

	// First call — file should be stored.
	rp.AddResult(newTestResult("http://example.com", true, []detection.FileInfo{file}))

	results := rp.GetResults()
	if got := len(results["http://example.com"].FilesDiscovered); got != 1 {
		t.Fatalf("after first add: expected 1 file, got %d", got)
	}

	// Second call with the same file — it should be de-duplicated (empty after filter).
	rp.AddResult(newTestResult("http://example.com", true, []detection.FileInfo{file}))

	results = rp.GetResults()
	// The second result overwrites the map entry with an empty dedupedFiles slice.
	if got := len(results["http://example.com"].FilesDiscovered); got != 0 {
		t.Errorf("after duplicate add: expected 0 new files, got %d", got)
	}
}

// TestGetSummary verifies the summary counts are correct.
func TestGetSummary(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Output = config.OutputHuman

	rp, err := result.NewResultProcessor(cfg)
	if err != nil {
		t.Fatalf("NewResultProcessor: %v", err)
	}
	defer rp.Close()

	rp.AddResult(newTestResult("http://vuln.com", true, []detection.FileInfo{{ShortName: "A"}}))
	rp.AddResult(newTestResult("http://safe.com", false, nil))

	summary := rp.GetSummary()
	if !strings.Contains(summary, "1 vulnerable") {
		t.Errorf("summary should contain '1 vulnerable', got: %s", summary)
	}
	if !strings.Contains(summary, "1 safe") {
		t.Errorf("summary should contain '1 safe', got: %s", summary)
	}
}
