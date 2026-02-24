// ------------------------------------------------------
// SSX v2 - Command Line Interface
// Advanced IIS short filename enumeration tool
// ------------------------------------------------------

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"

	"github.com/bitquark/shortscan/v2/pkg/config"
	"github.com/bitquark/shortscan/v2/pkg/scanner"
)

// CommandLineArgs represents command line arguments
type CommandLineArgs struct {
	URLs         []string `arg:"positional" help:"URL to scan (multiple URLs can be provided; a file containing URLs can be specified with an @ prefix)" placeholder:"URL"`
	
	// Scan options
	Wordlist     string   `arg:"-w,--wordlist" help:"Custom wordlist file" placeholder:"FILE"`
	RainbowTable string   `arg:"-r,--rainbow" help:"Rainbow table file for checksum matching" placeholder:"FILE"`
	
	// HTTP options
	Headers      []string `arg:"-H,--header,separate" help:"Custom headers (can be used multiple times)"`
	Concurrency  int      `arg:"-c,--concurrency" help:"Number of concurrent requests" default:"20"`
	Timeout      int      `arg:"-t,--timeout" help:"Request timeout in seconds" default:"10"`
	RateLimit    int      `arg:"--rate-limit" help:"Maximum requests per second" default:"100"`
	
	// Proxy options
	Proxy        string   `arg:"-p,--proxy" help:"Proxy URL (e.g., http://127.0.0.1:8080)" placeholder:"URL"`
	ProxyFile    string   `arg:"--proxy-file" help:"File containing proxy URLs for rotation" placeholder:"FILE"`
	
	// Detection options
	Detection    string   `arg:"-d,--detection" help:"Detection mode: auto, method, status, distance, timing, fuzzy, none" default:"auto"`
	Characters   string   `arg:"-C,--characters" help:"Characters to enumerate" default:"JFKGOTMYVHSPCANDXLRWEBQUIZ8549176320-_()&'!#\$%@^{}~"`
	Stabilize    bool     `arg:"-s,--stabilize" help:"Attempt to get coherent results from unstable servers"`
	Patience     int      `arg:"--patience" help:"Patience level (0-1)" default:"0"`
	
	// Scan behavior
	NoRecurse    bool     `arg:"-n,--no-recurse" help:"Disable recursive directory scanning"`
	VulnCheck    bool     `arg:"-V,--vuln-check" help:"Only check vulnerability without enumeration"`
	DeepScan     bool     `arg:"--deep" help:"Enable deep scanning mode"`
	
	// Output options
	Output       string   `arg:"-o,--output" help:"Output format: human, json, csv, html, markdown, xml" default:"human"`
	OutputFile   string   `arg:"-O,--output-file" help:"Write output to file" placeholder:"FILE"`
	FullURL      bool     `arg:"-F,--full-url" help:"Display full URLs in output"`
	Quiet        bool     `arg:"-q,--quiet" help:"Suppress all output except results"`
	Verbose      int      `arg:"-v,--verbose" help:"Verbosity level (0-2)" default:"0"`
	
	// Advanced options
	HTTP2        bool     `arg:"--http2" help:"Enable HTTP/2 support" default:"true"`
	NoTLSVerify  bool     `arg:"--insecure" help:"Skip TLS certificate verification" default:"true"`
	EnableTiming bool     `arg:"--timing" help:"Enable timing-based detection" default:"true"`
	EnableFuzzy  bool     `arg:"--fuzzy" help:"Enable fuzzy matching" default:"true"`
	
	// API server
	EnableAPI    bool     `arg:"--api" help:"Enable REST API server"`
	APIPort      int      `arg:"--api-port" help:"API server port" default:"8080"`
}

// Version returns version information
func (CommandLineArgs) Version() string {
	return color.New(color.FgBlue, color.Bold).Sprint("🌀 SSX v"+config.Version) +
		" · " + color.New(color.FgWhite, color.Bold).Sprint("Advanced IIS Short Filename Enumeration")
}

// Description returns the tool description
func (CommandLineArgs) Description() string {
	return "An advanced IIS short filename enumeration tool for security researchers"
}

func main() {
	// Parse command line arguments
	var args CommandLineArgs
	p := arg.MustParse(&args)
	
	// Validate detection mode
	detectionMode := strings.ToLower(args.Detection)
	validModes := map[string]bool{
		"auto": true, "method": true, "status": true, 
		"distance": true, "timing": true, "fuzzy": true, "none": true,
	}
	if !validModes[detectionMode] {
		p.Fail("detection must be one of: auto, method, status, distance, timing, fuzzy, none")
	}
	
	// Validate output format
	outputFormat := strings.ToLower(args.Output)
	validFormats := map[string]bool{
		"human": true, "json": true, "csv": true, 
		"html": true, "markdown": true, "xml": true,
	}
	if !validFormats[outputFormat] {
		p.Fail("output must be one of: human, json, csv, html, markdown, xml")
	}
	
	// Build configuration
	cfg := buildConfig(args)
	
	// Setup logging
	setupLogging(args.Verbose, args.Quiet)
	
	// Build URL list
	urls := buildURLList(args)
	if len(urls) == 0 {
		p.Fail("at least one URL is required")
	}
	
	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Handle interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[!] Interrupt received, shutting down...")
		cancel()
	}()
	
	// Create and run scanner
	s := scanner.NewScanner(cfg)
	defer s.Close()
	
	if err := s.Scan(ctx, urls); err != nil {
		log.Fatalf("Scan failed: %v", err)
	}
}

// buildConfig builds configuration from command line arguments
func buildConfig(args CommandLineArgs) *config.ScanConfig {
	cfg := config.DefaultConfig()
	
	// HTTP configuration
	cfg.Concurrency = args.Concurrency
	cfg.Timeout = time.Duration(args.Timeout) * time.Second
	cfg.RateLimit = args.RateLimit
	cfg.Headers = args.Headers
	
	// Proxy configuration
	cfg.ProxyURL = args.Proxy
	cfg.ProxyFile = args.ProxyFile
	cfg.ProxyRotation = args.ProxyFile != ""
	
	// Detection configuration
	cfg.DetectionMode = config.DetectionMode(strings.ToLower(args.Detection))
	cfg.Characters = args.Characters
	cfg.Stabilize = args.Stabilize
	cfg.Patience = args.Patience
	
	// Scan behavior
	cfg.Recurse = !args.NoRecurse
	cfg.VulnCheckOnly = args.VulnCheck
	cfg.DeepScan = args.DeepScan
	
	// Wordlist
	cfg.Wordlist = args.Wordlist
	cfg.RainbowTable = args.RainbowTable
	
	// Output configuration
	cfg.Output = config.OutputFormat(strings.ToLower(args.Output))
	cfg.OutputFile = args.OutputFile
	cfg.FullURL = args.FullURL
	cfg.Quiet = args.Quiet
	cfg.LogLevel = config.LogLevel(args.Verbose)
	
	// Advanced features
	cfg.EnableHTTP2 = args.HTTP2
	cfg.TLSSkipVerify = args.NoTLSVerify
	cfg.EnableTiming = args.EnableTiming
	cfg.EnableFuzzy = args.EnableFuzzy
	
	// API server
	cfg.EnableAPI = args.EnableAPI
	cfg.APIPort = args.APIPort
	
	return cfg
}

// buildURLList builds the URL list from arguments
func buildURLList(args CommandLineArgs) []string {
	urls := make([]string, 0)
	
	for _, arg := range args.URLs {
		// Check if this is a file reference
		if strings.HasPrefix(arg, "@") {
			filePath := strings.TrimPrefix(arg, "@")
			fileURLs := readURLsFromFile(filePath)
			urls = append(urls, fileURLs...)
		} else {
			urls = append(urls, arg)
		}
	}
	
	return urls
}

// readURLsFromFile reads URLs from a file
func readURLsFromFile(filePath string) []string {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Failed to open URL file: %v", err)
	}
	defer file.Close()
	
	urls := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}
	
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading URL file: %v", err)
	}
	
	return urls
}

// setupLogging configures the logger
func setupLogging(verbose int, quiet bool) {
	log.SetFormatter(&log.TextFormatter{
		DisableLevelTruncation: true,
		DisableTimestamp:       true,
	})
	
	if quiet {
		log.SetLevel(log.PanicLevel)
	} else {
		switch verbose {
		case 0:
			log.SetLevel(log.WarnLevel)
		case 1:
			log.SetLevel(log.InfoLevel)
		case 2:
			log.SetLevel(log.DebugLevel)
		default:
			log.SetLevel(log.TraceLevel)
		}
	}
}
