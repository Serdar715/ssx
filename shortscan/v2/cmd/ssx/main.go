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

	"github.com/Serdar715/ssx/shortscan/v2/pkg/api"
	"github.com/Serdar715/ssx/shortscan/v2/pkg/config"
	"github.com/Serdar715/ssx/shortscan/v2/pkg/scanner"
)

// CommandLineArgs represents command line arguments.
type CommandLineArgs struct {
	URLs []string `arg:"positional" help:"URL to scan (prefix with @ to read from a file)" placeholder:"URL"`

	// Scan options
	Wordlist     string `arg:"-w,--wordlist"  help:"Custom wordlist file"                         placeholder:"FILE"`
	RainbowTable string `arg:"-r,--rainbow"   help:"Rainbow table file for checksum matching"     placeholder:"FILE"`

	// HTTP options
	Headers     []string `arg:"-H,--header,separate" help:"Custom headers (repeatable)"`
	Concurrency int      `arg:"-c,--concurrency"     help:"Concurrent requests"           default:"20"`
	Timeout     int      `arg:"-t,--timeout"         help:"Request timeout in seconds"    default:"10"`
	RateLimit   int      `arg:"--rate-limit"          help:"Max requests per second"       default:"100"`

	// Proxy options
	Proxy     string `arg:"-x,--proxy"      help:"Proxy URL (e.g. http://127.0.0.1:8080, socks5://127.0.0.1:1080)" placeholder:"URL"`
	ProxyFile string `arg:"--proxy-file"    help:"File with proxy URLs for rotation"       placeholder:"FILE"`

	// Detection options
	Detection  string `arg:"-d,--detection"  help:"Detection mode: auto|method|status|distance|timing|fuzzy|none" default:"auto"`
	Characters string `arg:"-C,--characters" help:"Characters to enumerate"                                        default:"JFKGOTMYVHSPCANDXLRWEBQUIZ8549176320-_()&'!#\\$%@^{}~"`
	Stabilize  bool   `arg:"-s,--stabilize"  help:"Attempt to stabilise results on unstable servers"`
	Patience   int    `arg:"-p,--patience"   help:"Patience level (0=patient, 1=very patient)"                      default:"0"`

	// Scan behaviour
	NoRecurse bool `arg:"-n,--no-recurse" help:"Disable recursive directory scanning"`
	VulnCheck bool `arg:"-V,--vuln-check" help:"Only check vulnerability, no enumeration"`
	DeepScan  bool `arg:"--deep"          help:"Enable deep scanning mode"`

	// Output options
	Output     string `arg:"-o,--output"      help:"Output format: human|json|csv|html|markdown|xml" default:"human"`
	OutputFile string `arg:"-O,--output-file" help:"Write output to file"                            placeholder:"FILE"`
	FullURL    bool   `arg:"-F,--full-url"    help:"Display full URLs in output"`
	Quiet      bool   `arg:"-q,--quiet"       help:"Suppress all output except results"`
	Verbose    int    `arg:"-v,--verbose"     help:"Verbosity level (0-2)"                          default:"0"`

	// Advanced options
	HTTP2        bool `arg:"--http2"     help:"Enable HTTP/2 support"              default:"true"`
	NoTLSVerify  bool `arg:"--insecure"  help:"Skip TLS certificate verification" default:"true"`
	EnableTiming bool `arg:"--timing"    help:"Enable timing-based detection"     default:"true"`
	EnableFuzzy  bool `arg:"--fuzzy"     help:"Enable fuzzy matching"             default:"true"`

	// API server
	EnableAPI bool `arg:"--api"      help:"Enable REST API server"`
	APIPort   int  `arg:"--api-port" help:"API server port" default:"8080"`
}

// Version returns the version banner shown by --version.
func (CommandLineArgs) Version() string {
	return color.New(color.FgBlue, color.Bold).Sprint("🌀 SSX v"+config.Version) +
		" · " + color.New(color.FgWhite, color.Bold).Sprint("Advanced IIS Short Filename Enumeration")
}

// Description returns the tool description shown in help output.
func (CommandLineArgs) Description() string {
	return "An advanced IIS short filename enumeration tool for security researchers"
}

func main() {
	var args CommandLineArgs
	p := arg.MustParse(&args)

	// Validate detection mode.
	validModes := map[string]bool{
		"auto": true, "method": true, "status": true,
		"distance": true, "timing": true, "fuzzy": true, "none": true,
	}
	if !validModes[strings.ToLower(args.Detection)] {
		p.Fail("detection must be one of: auto, method, status, distance, timing, fuzzy, none")
	}

	// Validate output format.
	validFormats := map[string]bool{
		"human": true, "json": true, "csv": true,
		"html": true, "markdown": true, "xml": true,
	}
	if !validFormats[strings.ToLower(args.Output)] {
		p.Fail("output must be one of: human, json, csv, html, markdown, xml")
	}

	setupLogging(args.Verbose, args.Quiet)

	cfg := buildConfig(args)

	// Validate config — surface any remaining constraint violations early.
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	urls := buildURLList(args)
	if len(urls) == 0 {
		p.Fail("at least one URL is required")
	}

	// Root context with cancellation on interrupt.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[!] Interrupt received, shutting down…")
		cancel()
	}()

	// Optionally start the API server in the background.
	if cfg.EnableAPI {
		apiServer, err := api.NewServer(cfg)
		if err != nil {
			log.Fatalf("Failed to initialise API server: %v", err)
		}

		go func() {
			log.Infof("API server listening on :%d", cfg.APIPort)
			if listenErr := apiServer.Start(cfg.APIPort); listenErr != nil && ctx.Err() == nil {
				log.Errorf("API server error: %v", listenErr)
			}
		}()

		// Shut the API server down when the main context is cancelled.
		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = apiServer.Shutdown(shutdownCtx)
		}()
	}

	// Create and run the scanner.
	s, err := scanner.NewScanner(cfg)
	if err != nil {
		log.Fatalf("Failed to initialise scanner: %v", err)
	}
	defer s.Close()

	if err := s.Scan(ctx, urls); err != nil {
		log.Fatalf("Scan failed: %v", err)
	}
}

// buildConfig translates CLI arguments into a ScanConfig.
func buildConfig(args CommandLineArgs) *config.ScanConfig {
	cfg := config.DefaultConfig()

	cfg.Concurrency = args.Concurrency
	cfg.Timeout = time.Duration(args.Timeout) * time.Second
	cfg.RateLimit = args.RateLimit
	cfg.Headers = args.Headers

	cfg.ProxyURL = args.Proxy
	cfg.ProxyFile = args.ProxyFile
	cfg.ProxyRotation = args.ProxyFile != ""

	cfg.DetectionMode = config.DetectionMode(strings.ToLower(args.Detection))
	cfg.Characters = args.Characters
	cfg.Stabilize = args.Stabilize
	cfg.Patience = args.Patience

	cfg.Recurse = !args.NoRecurse
	cfg.VulnCheckOnly = args.VulnCheck
	cfg.DeepScan = args.DeepScan

	cfg.Wordlist = args.Wordlist
	cfg.RainbowTable = args.RainbowTable

	cfg.Output = config.OutputFormat(strings.ToLower(args.Output))
	cfg.OutputFile = args.OutputFile
	cfg.FullURL = args.FullURL
	cfg.Quiet = args.Quiet
	cfg.LogLevel = config.LogLevel(args.Verbose)

	cfg.EnableHTTP2 = args.HTTP2
	cfg.TLSSkipVerify = args.NoTLSVerify
	cfg.EnableTiming = args.EnableTiming
	cfg.EnableFuzzy = args.EnableFuzzy

	cfg.EnableAPI = args.EnableAPI
	cfg.APIPort = args.APIPort

	return cfg
}

// buildURLList expands @file references and collects all target URLs.
func buildURLList(args CommandLineArgs) []string {
	urls := make([]string, 0, len(args.URLs))

	for _, rawArg := range args.URLs {
		if strings.HasPrefix(rawArg, "@") {
			filePath := strings.TrimPrefix(rawArg, "@")
			fileURLs, err := readURLsFromFile(filePath)
			if err != nil {
				log.Fatalf("Failed to read URL file: %v", err)
			}
			urls = append(urls, fileURLs...)
		} else {
			urls = append(urls, rawArg)
		}
	}

	return urls
}

// readURLsFromFile reads non-empty, non-comment lines from a URL list file.
func readURLsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", filePath, err)
	}
	defer file.Close()

	urls := make([]string, 0)
	lineScanner := bufio.NewScanner(file)

	for lineScanner.Scan() {
		line := strings.TrimSpace(lineScanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}

	if scanErr := lineScanner.Err(); scanErr != nil {
		return nil, fmt.Errorf("read %q: %w", filePath, scanErr)
	}

	return urls, nil
}

// setupLogging configures the logrus logger based on verbosity and quiet flags.
func setupLogging(verbose int, quiet bool) {
	log.SetFormatter(&log.TextFormatter{
		DisableLevelTruncation: true,
		DisableTimestamp:       true,
	})

	if quiet {
		log.SetLevel(log.PanicLevel)
		return
	}

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
