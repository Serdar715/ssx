// ------------------------------------------------------
// Shortscan v2 - Configuration Module
// Advanced IIS short filename enumeration tool
// ------------------------------------------------------

package config

import (
	"time"
)

// Version information
const (
	Version   = "2.0.0"
	BuildDate = "2026-02-24"
)

// Default values
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
	URLs         []string `json:"urls" yaml:"urls"`
	URLFile      string   `json:"url_file" yaml:"url_file"`
	ExcludeFile  string   `json:"exclude_file" yaml:"exclude_file"`

	// HTTP configuration
	Concurrency    int           `json:"concurrency" yaml:"concurrency"`
	Timeout        time.Duration `json:"timeout" yaml:"timeout"`
	ConnectTimeout time.Duration `json:"connect_timeout" yaml:"connect_timeout"`
	RetryCount     int           `json:"retry_count" yaml:"retry_count"`
	RetryDelay     time.Duration `json:"retry_delay" yaml:"retry_delay"`
	MaxRedirects   int           `json:"max_redirects" yaml:"max_redirects"`

	// Rate limiting
	RateLimit      int           `json:"rate_limit" yaml:"rate_limit"`
	RateLimitBurst int           `json:"rate_limit_burst" yaml:"rate_limit_burst"`
	AdaptiveRate   bool          `json:"adaptive_rate" yaml:"adaptive_rate"`

	// Proxy configuration
	ProxyURL      string   `json:"proxy_url" yaml:"proxy_url"`
	ProxyFile     string   `json:"proxy_file" yaml:"proxy_file"`
	ProxyRotation bool     `json:"proxy_rotation" yaml:"proxy_rotation"`
	ProxyAuth     string   `json:"proxy_auth" yaml:"proxy_auth"`

	// Headers
	UserAgent string   `json:"user_agent" yaml:"user_agent"`
	Headers   []string `json:"headers" yaml:"headers"`
	Cookies   []string `json:"cookies" yaml:"cookies"`

	// Detection configuration
	DetectionMode  DetectionMode `json:"detection_mode" yaml:"detection_mode"`
	Characters     string        `json:"characters" yaml:"characters"`
	Autocomplete   bool          `json:"autocomplete" yaml:"autocomplete"`
	Stabilize      bool          `json:"stabilize" yaml:"stabilize"`
	Patience       int           `json:"patience" yaml:"patience"`

	// Scan behavior
	Recurse        bool `json:"recurse" yaml:"recurse"`
	FollowRedirect bool `json:"follow_redirect" yaml:"follow_redirect"`
	VulnCheckOnly  bool `json:"vuln_check_only" yaml:"vuln_check_only"`
	DeepScan       bool `json:"deep_scan" yaml:"deep_scan"`

	// Wordlist configuration
	Wordlist     string `json:"wordlist" yaml:"wordlist"`
	RainbowTable string `json:"rainbow_table" yaml:"rainbow_table"`

	// Output configuration
	Output       OutputFormat `json:"output" yaml:"output"`
	OutputFile   string       `json:"output_file" yaml:"output_file"`
	LogLevel     LogLevel     `json:"log_level" yaml:"log_level"`
	FullURL      bool         `json:"full_url" yaml:"full_url"`
	Quiet        bool         `json:"quiet" yaml:"quiet"`

	// Advanced features
	EnableHTTP2    bool `json:"enable_http2" yaml:"enable_http2"`
	TLSSkipVerify  bool `json:"tls_skip_verify" yaml:"tls_skip_verify"`
	EnableTiming   bool `json:"enable_timing" yaml:"enable_timing"`
	EnableFuzzy    bool `json:"enable_fuzzy" yaml:"enable_fuzzy"`

	// API server
	EnableAPI  bool   `json:"enable_api" yaml:"enable_api"`
	APIPort    int    `json:"api_port" yaml:"api_port"`
	APIKey     string `json:"api_key" yaml:"api_key"`

	// Plugins
	PluginDir  string   `json:"plugin_dir" yaml:"plugin_dir"`
	Plugins    []string `json:"plugins" yaml:"plugins"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *ScanConfig {
	return &ScanConfig{
		Concurrency:     DefaultConcurrency,
		Timeout:         DefaultTimeout,
		ConnectTimeout:  DefaultConnectTimeout,
		RetryCount:      DefaultRetryCount,
		RetryDelay:      DefaultRetryDelay,
		RateLimit:       DefaultRateLimit,
		RateLimitBurst:  DefaultConcurrency,
		MaxRedirects:    DefaultMaxRedirects,
		AdaptiveRate:    true,
		DetectionMode:   DetectionAuto,
		Characters:      "JFKGOTMYVHSPCANDXLRWEBQUIZ8549176320-_()&'!#$%@^{}~",
		Autocomplete:    true,
		Recurse:         true,
		FollowRedirect:  false,
		EnableHTTP2:     true,
		TLSSkipVerify:   true,
		Output:          OutputHuman,
		LogLevel:        LogWarn,
		UserAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/1337.00 (KHTML, like Gecko) Chrome/1337.0.0.0 Safari/1337.00",
		EnableTiming:    true,
		EnableFuzzy:     true,
		APIPort:         8080,
	}
}

// Validate validates the configuration
func (c *ScanConfig) Validate() error {
	// Add validation logic here
	return nil
}
