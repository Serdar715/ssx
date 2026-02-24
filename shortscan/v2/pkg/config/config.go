// ------------------------------------------------------
// Shortscan v2 - Configuration Module
// Advanced IIS short filename enumeration tool
// ------------------------------------------------------

package config

import (
	"fmt"
	"time"
)

// Version information
const (
	Version   = "2.0.0"
	BuildDate = "2026-02-24"
)

// Default connection / HTTP values
const (
	DefaultConcurrency    = 20
	DefaultTimeout        = 10 * time.Second
	DefaultRetryCount     = 3
	DefaultRetryDelay     = 2 * time.Second
	DefaultRateLimit      = 100 // requests per second
	DefaultBatchSize      = 100
	DefaultMaxRedirects   = 5
	DefaultConnectTimeout = 5 * time.Second
)

// Detection algorithm constants — keeps magic numbers in one place.
const (
	// TimingBaselines is the number of baseline requests used in timing detection.
	TimingBaselines = 10

	// TimingSampleWindow is the maximum number of timing samples kept in the rolling window.
	TimingSampleWindow = 100

	// TimingStdDevMultiplier is how many standard deviations above mean triggers an anomaly.
	TimingStdDevMultiplier = 2

	// MaxTildeIndex is the highest tilde variant to test (~1 … ~MaxTildeIndex).
	// Windows 2000+ creates at most 4 tilde variants per short name.
	MaxTildeIndex = 4

	// NegativeTildeOffset is the starting tilde value used for "non-existent" probes.
	// Tildes >= 5 cannot exist on Windows 2000+ systems.
	NegativeTildeOffset = 5

	// MaxFilenameLen is the maximum length of the short-name prefix in 8.3 format.
	MaxFilenameLen = 6

	// MaxExtensionLen is the maximum length of the short-name extension in 8.3 format.
	MaxExtensionLen = 3

	// NegativeCheckCount is the number of negative-status probes sent to establish a baseline.
	NegativeCheckCount = 4
)

// Proxy / rate-limiter tuning constants
const (
	// ProxyMaxFailures is the number of consecutive failures before a proxy is marked bad.
	ProxyMaxFailures = 3

	// AdaptiveSuccessThreshold is how many consecutive successes trigger a rate increase.
	AdaptiveSuccessThreshold = 10

	// AdaptiveFailureThreshold is how many consecutive failures trigger a rate decrease.
	AdaptiveFailureThreshold = 3

	// AdaptiveRateIncrement is the req/s added on each successful rate-up event.
	AdaptiveRateIncrement = 10

	// AdaptiveRateDecrement is the req/s removed on each rate-down event.
	AdaptiveRateDecrement = 20
)

// API server constant
const (
	// DefaultAPIPort is the default port for the REST API server.
	DefaultAPIPort = 8080
)

// DetectionMode represents the enumeration detection method
type DetectionMode string

const (
	DetectionAuto     DetectionMode = "auto"
	DetectionMethod   DetectionMode = "method"
	DetectionStatus   DetectionMode = "status"
	DetectionDistance DetectionMode = "distance"
	DetectionTiming   DetectionMode = "timing"
	DetectionFuzzy    DetectionMode = "fuzzy"
	DetectionNone     DetectionMode = "none"
)

// validDetectionModes is used by Validate() to check the configured mode.
var validDetectionModes = map[DetectionMode]struct{}{
	DetectionAuto:     {},
	DetectionMethod:   {},
	DetectionStatus:   {},
	DetectionDistance: {},
	DetectionTiming:   {},
	DetectionFuzzy:    {},
	DetectionNone:     {},
}

// OutputFormat represents the output format type
type OutputFormat string

const (
	OutputHuman    OutputFormat = "human"
	OutputJSON     OutputFormat = "json"
	OutputCSV      OutputFormat = "csv"
	OutputHTML     OutputFormat = "html"
	OutputMarkdown OutputFormat = "markdown"
	OutputXML      OutputFormat = "xml"
)

// validOutputFormats is used by Validate() to check the configured format.
var validOutputFormats = map[OutputFormat]struct{}{
	OutputHuman:    {},
	OutputJSON:     {},
	OutputCSV:      {},
	OutputHTML:     {},
	OutputMarkdown: {},
	OutputXML:      {},
}

// LogLevel represents logging verbosity
type LogLevel int

const (
	LogQuiet LogLevel = iota
	LogWarn
	LogInfo
	LogDebug
	LogTrace
)

// ScanConfig holds all configuration for a scan
type ScanConfig struct {
	// Target configuration
	URLs        []string `json:"urls"         yaml:"urls"`
	URLFile     string   `json:"url_file"     yaml:"url_file"`
	ExcludeFile string   `json:"exclude_file" yaml:"exclude_file"`

	// HTTP configuration
	Concurrency    int           `json:"concurrency"     yaml:"concurrency"`
	Timeout        time.Duration `json:"timeout"         yaml:"timeout"`
	ConnectTimeout time.Duration `json:"connect_timeout" yaml:"connect_timeout"`
	RetryCount     int           `json:"retry_count"     yaml:"retry_count"`
	RetryDelay     time.Duration `json:"retry_delay"     yaml:"retry_delay"`
	MaxRedirects   int           `json:"max_redirects"   yaml:"max_redirects"`

	// Rate limiting
	RateLimit      int  `json:"rate_limit"       yaml:"rate_limit"`
	RateLimitBurst int  `json:"rate_limit_burst" yaml:"rate_limit_burst"`
	AdaptiveRate   bool `json:"adaptive_rate"    yaml:"adaptive_rate"`

	// Proxy configuration
	ProxyURL      string `json:"proxy_url"      yaml:"proxy_url"`
	ProxyFile     string `json:"proxy_file"     yaml:"proxy_file"`
	ProxyRotation bool   `json:"proxy_rotation" yaml:"proxy_rotation"`
	ProxyAuth     string `json:"proxy_auth"     yaml:"proxy_auth"`

	// Headers
	UserAgent string   `json:"user_agent" yaml:"user_agent"`
	Headers   []string `json:"headers"    yaml:"headers"`
	Cookies   []string `json:"cookies"    yaml:"cookies"`

	// Detection configuration
	DetectionMode DetectionMode `json:"detection_mode" yaml:"detection_mode"`
	Characters    string        `json:"characters"     yaml:"characters"`
	Autocomplete  bool          `json:"autocomplete"   yaml:"autocomplete"`
	Stabilize     bool          `json:"stabilize"      yaml:"stabilize"`
	Patience      int           `json:"patience"       yaml:"patience"`

	// Scan behavior
	Recurse        bool `json:"recurse"          yaml:"recurse"`
	FollowRedirect bool `json:"follow_redirect"  yaml:"follow_redirect"`
	VulnCheckOnly  bool `json:"vuln_check_only"  yaml:"vuln_check_only"`
	DeepScan       bool `json:"deep_scan"        yaml:"deep_scan"`

	// Wordlist configuration
	Wordlist     string `json:"wordlist"      yaml:"wordlist"`
	RainbowTable string `json:"rainbow_table" yaml:"rainbow_table"`

	// Output configuration
	Output     OutputFormat `json:"output"      yaml:"output"`
	OutputFile string       `json:"output_file" yaml:"output_file"`
	LogLevel   LogLevel     `json:"log_level"   yaml:"log_level"`
	FullURL    bool         `json:"full_url"    yaml:"full_url"`
	Quiet      bool         `json:"quiet"       yaml:"quiet"`

	// Advanced features
	EnableHTTP2   bool `json:"enable_http2"   yaml:"enable_http2"`
	TLSSkipVerify bool `json:"tls_skip_verify" yaml:"tls_skip_verify"`
	EnableTiming  bool `json:"enable_timing"  yaml:"enable_timing"`
	EnableFuzzy   bool `json:"enable_fuzzy"   yaml:"enable_fuzzy"`

	// API server
	EnableAPI bool   `json:"enable_api" yaml:"enable_api"`
	APIPort   int    `json:"api_port"   yaml:"api_port"`
	APIKey    string `json:"api_key"    yaml:"api_key"`

	// Plugins
	PluginDir string   `json:"plugin_dir" yaml:"plugin_dir"`
	Plugins   []string `json:"plugins"    yaml:"plugins"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *ScanConfig {
	return &ScanConfig{
		Concurrency:    DefaultConcurrency,
		Timeout:        DefaultTimeout,
		ConnectTimeout: DefaultConnectTimeout,
		RetryCount:     DefaultRetryCount,
		RetryDelay:     DefaultRetryDelay,
		RateLimit:      DefaultRateLimit,
		RateLimitBurst: DefaultConcurrency,
		MaxRedirects:   DefaultMaxRedirects,
		AdaptiveRate:   true,
		DetectionMode:  DetectionAuto,
		Characters:     "JFKGOTMYVHSPCANDXLRWEBQUIZ8549176320-_()&'!#$%@^{}~",
		Autocomplete:   true,
		Recurse:        true,
		FollowRedirect: false,
		EnableHTTP2:    true,
		TLSSkipVerify:  true,
		Output:         OutputHuman,
		LogLevel:       LogWarn,
		UserAgent:      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/1337.00 (KHTML, like Gecko) Chrome/1337.0.0.0 Safari/1337.00",
		EnableTiming:   true,
		EnableFuzzy:    true,
		APIPort:        DefaultAPIPort,
	}
}

// Validate validates the configuration and returns a descriptive error if invalid.
func (c *ScanConfig) Validate() error {
	if c.Concurrency < 1 {
		return fmt.Errorf("concurrency must be at least 1, got %d", c.Concurrency)
	}

	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive, got %v", c.Timeout)
	}

	if c.ConnectTimeout <= 0 {
		return fmt.Errorf("connect_timeout must be positive, got %v", c.ConnectTimeout)
	}

	if c.RateLimit < 1 {
		return fmt.Errorf("rate_limit must be at least 1, got %d", c.RateLimit)
	}

	if c.RetryCount < 0 {
		return fmt.Errorf("retry_count cannot be negative, got %d", c.RetryCount)
	}

	if c.MaxRedirects < 0 {
		return fmt.Errorf("max_redirects cannot be negative, got %d", c.MaxRedirects)
	}

	if _, ok := validDetectionModes[c.DetectionMode]; !ok {
		return fmt.Errorf("unknown detection_mode %q", c.DetectionMode)
	}

	if _, ok := validOutputFormats[c.Output]; !ok {
		return fmt.Errorf("unknown output format %q", c.Output)
	}

	if c.Characters == "" {
		return fmt.Errorf("characters must not be empty")
	}

	if c.Patience < 0 || c.Patience > 1 {
		return fmt.Errorf("patience must be 0 or 1, got %d", c.Patience)
	}

	if c.EnableAPI && (c.APIPort < 1 || c.APIPort > 65535) {
		return fmt.Errorf("api_port must be between 1 and 65535, got %d", c.APIPort)
	}

	return nil
}
