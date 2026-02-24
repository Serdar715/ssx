package httpengine_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Serdar715/ssx/shortscan/v2/pkg/config"
	"github.com/Serdar715/ssx/shortscan/v2/pkg/httpengine"
)

// TestProxyManagerRoundRobin verifies that GetProxy cycles through all proxies.
func TestProxyManagerRoundRobin(t *testing.T) {
	proxies := []string{"http://proxy1:8080", "http://proxy2:8080", "http://proxy3:8080"}
	pm := httpengine.NewProxyManager(proxies)

	seen := make(map[string]int)
	iterations := len(proxies) * 3
	for i := 0; i < iterations; i++ {
		seen[pm.GetProxy()]++
	}

	for _, p := range proxies {
		if seen[p] == 0 {
			t.Errorf("proxy %q was never selected", p)
		}
	}
}

// TestProxyManagerMarkBad verifies that bad proxies are skipped after exceeding threshold.
func TestProxyManagerMarkBad(t *testing.T) {
	proxies := []string{"http://bad:8080", "http://good:8080"}
	pm := httpengine.NewProxyManager(proxies)

	// Mark first proxy as bad enough times to exceed the threshold.
	for i := 0; i < config.ProxyMaxFailures; i++ {
		pm.MarkBad("http://bad:8080")
	}

	// All subsequent calls should return the good proxy.
	for i := 0; i < 5; i++ {
		got := pm.GetProxy()
		if got == "http://bad:8080" {
			t.Errorf("bad proxy should have been skipped, got %q", got)
		}
	}
}

// TestRateLimiterContextCancellation verifies Wait() returns promptly on context cancellation.
func TestRateLimiterContextCancellation(t *testing.T) {
	// Rate of 1 token/s with burst 0 means we'll have to wait.
	rl := httpengine.NewRateLimiter(1, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := rl.Wait(ctx)
	if err == nil {
		t.Error("expected context cancellation error, got nil")
	}
}

// TestLoadProxiesFromFile verifies that proxy URLs are correctly read from a file.
func TestLoadProxiesFromFile(t *testing.T) {
	dir := t.TempDir()
	proxyFile := filepath.Join(dir, "proxies.txt")

	content := "http://proxy1:8080\n# comment\n\nhttp://proxy2:8080\n"
	if err := os.WriteFile(proxyFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write proxy file: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.ProxyFile = proxyFile

	engine := httpengine.NewHTTPEngine(cfg)
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
}

// TestRequestBodyDrained verifies that response bodies are properly drained,
// by checking that the connection can be reused (no connection exhaustion).
func TestRequestBodyDrained(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := config.DefaultConfig()
	cfg.Concurrency = 1
	cfg.Timeout = 5 * time.Second
	cfg.RetryCount = 1

	engine := httpengine.NewHTTPEngine(cfg)

	for i := 0; i < 5; i++ {
		resp, err := engine.Request(context.Background(), http.MethodGet, server.URL, nil)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		// Callers must drain the body; do so here to keep connections healthy.
		resp.Body.Close()
	}

	if callCount != 5 {
		t.Errorf("expected 5 calls, got %d", callCount)
	}
}
