// ------------------------------------------------------
// Shortscan v2 - Advanced HTTP Engine
// HTTP/2, connection pooling, proxy rotation, rate limiting
// ------------------------------------------------------

package httpengine

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bitquark/shortscan/v2/pkg/config"
	"golang.org/x/net/http2"
)

// Stats holds HTTP statistics.
// All fields are protected by the engine mutex; do NOT mix atomic ops on these fields.
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

// ProxyManager handles proxy rotation with a dedicated read-write mutex.
type ProxyManager struct {
	proxies    []string
	current    int
	badProxies map[string]int // proxy → consecutive failure count
	mu         sync.Mutex
}

// NewProxyManager creates a new proxy manager from a list of proxy URLs.
func NewProxyManager(proxies []string) *ProxyManager {
	return &ProxyManager{
		proxies:    proxies,
		badProxies: make(map[string]int),
	}
}

// GetProxy returns the next non-bad proxy using round-robin selection.
// If all proxies are bad the failure counters are reset and the first proxy is returned.
func (pm *ProxyManager) GetProxy() string {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(pm.proxies) == 0 {
		return ""
	}

	// Try each proxy in order, skipping bad ones.
	for range pm.proxies {
		pm.current = (pm.current + 1) % len(pm.proxies)
		proxy := pm.proxies[pm.current]
		if pm.badProxies[proxy] < config.ProxyMaxFailures {
			return proxy
		}
	}

	// All proxies exceeded failure threshold — reset and fall back to first.
	pm.badProxies = make(map[string]int)
	pm.current = 0
	return pm.proxies[0]
}

// MarkBad records a failure for the given proxy URL.
func (pm *ProxyManager) MarkBad(proxyURL string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.badProxies[proxyURL]++
}

// RateLimiter implements an adaptive token-bucket rate limiter.
// The mutex is held only while reading/writing token state, not during sleeps.
type RateLimiter struct {
	mu           sync.Mutex
	tokens       int
	lastCheck    time.Time
	currentRate  int
	burst        int
	minRate      int
	maxRate      int
	successCount int
	failCount    int
}

// NewRateLimiter creates a new rate limiter with the given rate and burst values.
func NewRateLimiter(rate, burst int) *RateLimiter {
	return &RateLimiter{
		tokens:      burst,
		lastCheck:   time.Now(),
		currentRate: rate,
		burst:       burst,
		minRate:     max(1, rate/10),
		maxRate:     rate * 2,
	}
}

// Wait blocks until a token is available or the context is cancelled.
// The mutex is NOT held during the sleep, so other goroutines are not blocked.
func (rl *RateLimiter) Wait(waitCtx context.Context) error {
	// Refill tokens outside the lock to calculate wait duration.
	rl.mu.Lock()
	now := time.Now()
	elapsed := now.Sub(rl.lastCheck)
	rl.lastCheck = now
	tokensToAdd := int(elapsed.Seconds() * float64(rl.currentRate))
	rl.tokens = min(rl.burst, rl.tokens+tokensToAdd)

	if rl.tokens > 0 {
		rl.tokens--
		rl.mu.Unlock()
		return nil
	}

	// Calculate how long we need to wait for one token.
	waitDuration := time.Second / time.Duration(rl.currentRate)
	rl.mu.Unlock()

	// Sleep without holding the lock.
	select {
	case <-waitCtx.Done():
		return waitCtx.Err()
	case <-time.After(waitDuration):
		return nil
	}
}

// RecordSuccess records a successful request and may increase the rate.
func (rl *RateLimiter) RecordSuccess() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.successCount++
	if rl.successCount >= config.AdaptiveSuccessThreshold {
		rl.currentRate = min(rl.maxRate, rl.currentRate+config.AdaptiveRateIncrement)
		rl.successCount = 0
	}
}

// RecordFailure records a failed request and may decrease the rate.
func (rl *RateLimiter) RecordFailure() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.failCount++
	if rl.failCount >= config.AdaptiveFailureThreshold {
		rl.currentRate = max(rl.minRate, rl.currentRate-config.AdaptiveRateDecrement)
		rl.failCount = 0
	}
}

// HTTPEngine is the advanced HTTP client with connection pooling and proxy rotation.
type HTTPEngine struct {
	cfg          *config.ScanConfig
	clientPool   []*http.Client
	poolIndex    atomic.Int32
	proxyManager *ProxyManager
	rateLimiter  *RateLimiter

	mu        sync.Mutex // protects stats and latencies
	stats     Stats
	latencies []time.Duration
}

// NewHTTPEngine creates a new HTTP engine configured from cfg.
func NewHTTPEngine(cfg *config.ScanConfig) *HTTPEngine {
	engine := &HTTPEngine{
		cfg:         cfg,
		rateLimiter: NewRateLimiter(cfg.RateLimit, cfg.RateLimitBurst),
		latencies:   make([]time.Duration, 0, config.TimingSampleWindow),
	}

	// Setup proxy manager if configured.
	if cfg.ProxyFile != "" || cfg.ProxyURL != "" {
		proxies := loadProxies(cfg)
		engine.proxyManager = NewProxyManager(proxies)
	}

	// Create connection pool with one client per concurrency slot.
	engine.clientPool = make([]*http.Client, cfg.Concurrency)
	for idx := range engine.clientPool {
		engine.clientPool[idx] = engine.createClient()
	}

	return engine
}

// createClient creates an HTTP client with proper configuration.
func (e *HTTPEngine) createClient() *http.Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   e.cfg.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   20,
		DisableCompression:    false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: e.cfg.TLSSkipVerify, //nolint:gosec // user-controlled option
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		Proxy: e.getProxyFunc(),
	}

	if e.cfg.EnableHTTP2 {
		http2.ConfigureTransport(transport) //nolint:errcheck // best-effort HTTP/2 upgrade
	}

	return &http.Client{
		Transport: transport,
		Timeout:   e.cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !e.cfg.FollowRedirect {
				return http.ErrUseLastResponse
			}
			if len(via) >= e.cfg.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", e.cfg.MaxRedirects)
			}
			return nil
		},
	}
}

// getProxyFunc returns the proxy selector function for http.Transport.
func (e *HTTPEngine) getProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if e.proxyManager == nil {
			return http.ProxyFromEnvironment(req)
		}

		proxyStr := e.proxyManager.GetProxy()
		if proxyStr == "" {
			return http.ProxyFromEnvironment(req)
		}

		proxyURL, err := url.Parse(proxyStr)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyStr, err)
		}

		if e.cfg.ProxyAuth != "" {
			username, password, _ := strings.Cut(e.cfg.ProxyAuth, ":")
			if password != "" {
				proxyURL.User = url.UserPassword(username, password)
			} else {
				proxyURL.User = url.User(username)
			}
		}

		return proxyURL, nil
	}
}

// Request performs an HTTP request using the configured retry count.
// The caller is responsible for draining and closing resp.Body.
func (e *HTTPEngine) Request(ctx context.Context, method, rawURL string, headers map[string]string) (*http.Response, error) {
	return e.RequestWithRetry(ctx, method, rawURL, headers, e.cfg.RetryCount)
}

// RequestWithRetry performs an HTTP request with a custom retry count.
// The caller is responsible for draining and closing resp.Body.
func (e *HTTPEngine) RequestWithRetry(ctx context.Context, method, rawURL string, headers map[string]string, maxRetries int) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Respect rate limit.
		if err := e.rateLimiter.Wait(ctx); err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
		if err != nil {
			// Malformed URL is not retryable.
			return nil, fmt.Errorf("build request: %w", err)
		}

		req.Header.Set("User-Agent", e.cfg.UserAgent)

		for k, v := range headers {
			req.Header.Set(k, v)
		}

		for _, h := range e.cfg.Headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				if strings.EqualFold(key, "host") {
					req.Host = val
				} else {
					req.Header.Set(key, val)
				}
			}
		}

		for _, cookie := range e.cfg.Cookies {
			req.Header.Add("Cookie", cookie)
		}

		idx := int(e.poolIndex.Add(1)) % len(e.clientPool)
		client := e.clientPool[idx]

		start := time.Now()
		resp, doErr := client.Do(req)
		latency := time.Since(start)

		e.updateStats(latency, resp, doErr)

		if doErr == nil {
			e.rateLimiter.RecordSuccess()
			return resp, nil
		}

		lastErr = doErr

		if e.proxyManager != nil {
			// Mark the proxy that was in use as bad.
			if proxy := e.proxyManager.GetProxy(); proxy != "" {
				e.proxyManager.MarkBad(proxy)
			}
		}

		e.rateLimiter.RecordFailure()

		if attempt < maxRetries-1 {
			backoff := e.cfg.RetryDelay * time.Duration(math.Pow(2, float64(attempt)))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
	}

	return nil, lastErr
}

// updateStats updates HTTP statistics under the engine mutex.
func (e *HTTPEngine) updateStats(latency time.Duration, resp *http.Response, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.stats.TotalRequests++

	if err != nil {
		e.stats.FailedRequests++
	} else {
		e.stats.SuccessRequests++

		if resp != nil {
			e.stats.BytesReceived += resp.ContentLength
		}
	}

	// Rolling latency window.
	e.latencies = append(e.latencies, latency)
	if len(e.latencies) > config.TimingSampleWindow {
		e.latencies = e.latencies[1:]
	}

	// Recalculate average.
	var total time.Duration
	for _, l := range e.latencies {
		total += l
	}
	e.stats.AvgLatency = total / time.Duration(len(e.latencies))

	if e.stats.MinLatency == 0 || latency < e.stats.MinLatency {
		e.stats.MinLatency = latency
	}
	if latency > e.stats.MaxLatency {
		e.stats.MaxLatency = latency
	}
}

// GetStats returns a snapshot of the current HTTP statistics.
func (e *HTTPEngine) GetStats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}

// RecordRetry increments the retry counter; called by callers that implement their own retry logic.
func (e *HTTPEngine) RecordRetry() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats.Retries++
}

// loadProxies loads proxy URLs from the configuration.
// If ProxyURL is set it is added first; if ProxyFile is set every non-empty,
// non-comment line in the file is treated as a proxy URL.
func loadProxies(cfg *config.ScanConfig) []string {
	proxies := make([]string, 0)

	if cfg.ProxyURL != "" {
		proxies = append(proxies, cfg.ProxyURL)
	}

	if cfg.ProxyFile != "" {
		fileProxies, err := readLinesFromFile(cfg.ProxyFile)
		if err != nil {
			// Non-fatal: log and continue with whatever we have.
			fmt.Fprintf(os.Stderr, "[WARN] proxy file %q: %v\n", cfg.ProxyFile, err)
		} else {
			proxies = append(proxies, fileProxies...)
		}
	}

	return proxies
}

// readLinesFromFile reads a text file and returns non-empty, non-comment lines.
func readLinesFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", filePath, err)
	}
	defer file.Close()

	lines := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}

	if scanErr := scanner.Err(); scanErr != nil {
		return nil, fmt.Errorf("read %q: %w", filePath, scanErr)
	}

	return lines, nil
}
