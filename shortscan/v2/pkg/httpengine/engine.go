// ------------------------------------------------------
// Shortscan v2 - Advanced HTTP Engine
// HTTP/2, connection pooling, proxy rotation, rate limiting
// ------------------------------------------------------

package httpengine

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bitquark/shortscan/v2/pkg/config"
	"golang.org/x/net/http2"
)

// Stats holds HTTP statistics
type Stats struct {
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	Retries         int64
	BytesSent       int64
	BytesReceived   int64
	AvgLatency      time.Duration
	MinLatency      time.Duration
	MaxLatency      time.Duration
}

// ProxyManager handles proxy rotation
type ProxyManager struct {
	proxies    []string
	current    int32
	mu         sync.RWMutex
	badProxies map[string]int // proxy -> failure count
}

// NewProxyManager creates a new proxy manager
func NewProxyManager(proxies []string) *ProxyManager {
	return &ProxyManager{
		proxies:    proxies,
		badProxies: make(map[string]int),
	}
}

// GetProxy returns the next available proxy
func (pm *ProxyManager) GetProxy() string {
	if len(pm.proxies) == 0 {
		return ""
	}
	
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	// Try to find a working proxy
	for i := 0; i < len(pm.proxies); i++ {
		idx := atomic.AddInt32(&pm.current, 1) % int32(len(pm.proxies))
		proxy := pm.proxies[idx]
		
		// Skip bad proxies (more than 3 failures)
		if pm.badProxies[proxy] < 3 {
			return proxy
		}
	}
	
	// If all proxies are bad, reset and return first
	pm.current = 0
	return pm.proxies[0]
}

// MarkBad marks a proxy as bad
func (pm *ProxyManager) MarkBad(proxy string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.badProxies[proxy]++
}

// RateLimiter implements adaptive rate limiting
type RateLimiter struct {
	rate      int
	burst     int
	tokens    int
	lastCheck time.Time
	mu        sync.Mutex
	
	// Adaptive rate limiting
	successCount int
	failCount    int
	currentRate  int
	minRate      int
	maxRate      int
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate, burst int) *RateLimiter {
	return &RateLimiter{
		rate:       rate,
		burst:      burst,
		tokens:     burst,
		lastCheck:  time.Now(),
		currentRate: rate,
		minRate:    rate / 10,
		maxRate:    rate * 2,
	}
}

// Wait blocks until a token is available
func (rl *RateLimiter) Wait(ctx context.Context) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	elapsed := now.Sub(rl.lastCheck)
	rl.lastCheck = now
	
	// Add tokens based on elapsed time
	tokensToAdd := int(elapsed.Seconds() * float64(rl.currentRate))
	rl.tokens = min(rl.burst, rl.tokens+tokensToAdd)
	
	if rl.tokens > 0 {
		rl.tokens--
		return nil
	}
	
	// Wait for next token
	waitTime := time.Second / time.Duration(rl.currentRate)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(waitTime):
		return nil
	}
}

// RecordSuccess records a successful request for adaptive rate limiting
func (rl *RateLimiter) RecordSuccess() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	rl.successCount++
	
	// Increase rate after 10 successes
	if rl.successCount >= 10 {
		rl.currentRate = min(rl.maxRate, rl.currentRate+10)
		rl.successCount = 0
	}
}

// RecordFailure records a failed request for adaptive rate limiting
func (rl *RateLimiter) RecordFailure() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	rl.failCount++
	
	// Decrease rate after 3 failures
	if rl.failCount >= 3 {
		rl.currentRate = max(rl.minRate, rl.currentRate-20)
		rl.failCount = 0
	}
}

// HTTPEngine is the advanced HTTP client
type HTTPEngine struct {
	config        *config.ScanConfig
	client        *http.Client
	clientPool    []*http.Client
	poolIndex     int32
	proxyManager  *ProxyManager
	rateLimiter   *RateLimiter
	stats         Stats
	mu            sync.RWMutex
	latencies     []time.Duration
}

// NewHTTPEngine creates a new HTTP engine
func NewHTTPEngine(cfg *config.ScanConfig) *HTTPEngine {
	engine := &HTTPEngine{
		config:      cfg,
		rateLimiter: NewRateLimiter(cfg.RateLimit, cfg.RateLimitBurst),
		latencies:   make([]time.Duration, 0, 1000),
	}
	
	// Setup proxy manager if configured
	if cfg.ProxyFile != "" || cfg.ProxyURL != "" {
		proxies := loadProxies(cfg)
		engine.proxyManager = NewProxyManager(proxies)
	}
	
	// Create connection pool with multiple clients
	engine.clientPool = make([]*http.Client, cfg.Concurrency)
	for i := 0; i < cfg.Concurrency; i++ {
		engine.clientPool[i] = engine.createClient()
	}
	engine.client = engine.clientPool[0]
	
	return engine
}

// createClient creates an HTTP client with proper configuration
func (e *HTTPEngine) createClient() *http.Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   e.config.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   20,
		DisableCompression:    false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: e.config.TLSSkipVerify,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		Proxy: e.getProxyFunc(),
	}
	
	// Enable HTTP/2
	if e.config.EnableHTTP2 {
		http2.ConfigureTransport(transport)
	}
	
	return &http.Client{
		Transport: transport,
		Timeout:   e.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !e.config.FollowRedirect {
				return http.ErrUseLastResponse
			}
			if len(via) >= e.config.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", e.config.MaxRedirects)
			}
			return nil
		},
	}
}

// getProxyFunc returns the proxy function
func (e *HTTPEngine) getProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if e.proxyManager == nil {
			return http.ProxyFromEnvironment(req)
		}
		
		proxy := e.proxyManager.GetProxy()
		if proxy == "" {
			return http.ProxyFromEnvironment(req)
		}
		
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}
		
		// Add auth if configured
		if e.config.ProxyAuth != "" {
			proxyURL.User, _ = url.ParseUserinfo(e.config.ProxyAuth)
		}
		
		return proxyURL, nil
	}
}

// Request performs an HTTP request with retry logic
func (e *HTTPEngine) Request(ctx context.Context, method, url string, headers map[string]string) (*http.Response, error) {
	return e.RequestWithRetry(ctx, method, url, headers, e.config.RetryCount)
}

// RequestSimple performs a simple HTTP request without custom headers
func (e *HTTPEngine) RequestSimple(ctx context.Context, method, urlStr string) (*http.Response, error) {
	return e.Request(ctx, method, urlStr, nil)
}

// RequestWithRetry performs an HTTP request with custom retry count
func (e *HTTPEngine) RequestWithRetry(ctx context.Context, method, url string, headers map[string]string, maxRetries int) (*http.Response, error) {
	var lastErr error
	var resp *http.Response
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		// Rate limiting
		if err := e.rateLimiter.Wait(ctx); err != nil {
			return nil, err
		}
		
		// Create request
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return nil, err
		}
		
		// Set headers
		req.Header.Set("User-Agent", e.config.UserAgent)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		
		// Parse and set custom headers from config
		for _, h := range e.config.Headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				if strings.ToLower(strings.TrimSpace(parts[0])) == "host" {
					req.Host = strings.TrimSpace(parts[1])
				} else {
					req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
				}
			}
		}
		
		// Set cookies
		for _, c := range e.config.Cookies {
			req.Header.Add("Cookie", c)
		}
		
		// Get client from pool
		clientIdx := atomic.AddInt32(&e.poolIndex, 1) % int32(len(e.clientPool))
		client := e.clientPool[clientIdx]
		
		// Execute request
		start := time.Now()
		resp, lastErr = client.Do(req)
		latency := time.Since(start)
		
		// Update stats
		e.updateStats(latency, resp, lastErr)
		
		if lastErr == nil {
			e.rateLimiter.RecordSuccess()
			return resp, nil
		}
		
		// Mark proxy as bad if using proxy rotation
		if e.proxyManager != nil {
			e.proxyManager.MarkBad(e.proxyManager.GetProxy())
		}
		
		e.rateLimiter.RecordFailure()
		atomic.AddInt64(&e.stats.Retries, 1)
		
		// Exponential backoff
		if attempt < maxRetries-1 {
			backoff := e.config.RetryDelay * time.Duration(math.Pow(2, float64(attempt)))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
	}
	
	return resp, lastErr
}

// updateStats updates HTTP statistics
func (e *HTTPEngine) updateStats(latency time.Duration, resp *http.Response, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	
	atomic.AddInt64(&e.stats.TotalRequests, 1)
	
	if err != nil {
		atomic.AddInt64(&e.stats.FailedRequests, 1)
	} else {
		atomic.AddInt64(&e.stats.SuccessRequests, 1)
	}
	
	// Track latencies
	e.latencies = append(e.latencies, latency)
	if len(e.latencies) > 100 {
		e.latencies = e.latencies[1:]
	}
	
	// Calculate average
	var total time.Duration
	for _, l := range e.latencies {
		total += l
	}
	e.stats.AvgLatency = total / time.Duration(len(e.latencies))
	
	// Min/Max
	if e.stats.MinLatency == 0 || latency < e.stats.MinLatency {
		e.stats.MinLatency = latency
	}
	if latency > e.stats.MaxLatency {
		e.stats.MaxLatency = latency
	}
}

// GetStats returns current statistics
func (e *HTTPEngine) GetStats() Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stats
}

// loadProxies loads proxies from configuration
func loadProxies(cfg *config.ScanConfig) []string {
	proxies := make([]string, 0)
	
	if cfg.ProxyURL != "" {
		proxies = append(proxies, cfg.ProxyURL)
	}
	
	// TODO: Load from file if ProxyFile is set
	
	return proxies
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
