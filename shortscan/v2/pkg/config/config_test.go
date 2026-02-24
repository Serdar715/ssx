package config_test

import (
	"testing"
	"time"

	"github.com/Serdar715/ssx/shortscan/v2/pkg/config"
)

// TestDefaultConfigIsValid ensures DefaultConfig passes its own Validate().
func TestDefaultConfigIsValid(t *testing.T) {
	cfg := config.DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("DefaultConfig should be valid: %v", err)
	}
}

func TestValidateConcurrencyZero(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Concurrency = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for Concurrency=0")
	}
}

func TestValidateNegativeTimeout(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Timeout = -1 * time.Second
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for negative Timeout")
	}
}

func TestValidateZeroTimeout(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Timeout = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for zero Timeout")
	}
}

func TestValidateUnknownDetectionMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DetectionMode = "bogus"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for unknown DetectionMode")
	}
}

func TestValidateUnknownOutputFormat(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Output = "yaml"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for unknown Output format")
	}
}

func TestValidateEmptyCharacters(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Characters = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty Characters")
	}
}

func TestValidateInvalidPatience(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Patience = 2
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for Patience=2")
	}
}

func TestValidateInvalidAPIPort(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.EnableAPI = true
	cfg.APIPort = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for APIPort=0 when EnableAPI=true")
	}
}

func TestValidateNegativeRateLimit(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RateLimit = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for RateLimit=0")
	}
}
