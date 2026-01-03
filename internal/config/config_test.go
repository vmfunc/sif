/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package config

import (
	"testing"
	"time"
)

func TestSettingsDefaults(t *testing.T) {
	settings := &Settings{}

	// noscan should default to false (base scan runs by default)
	if settings.NoScan != false {
		t.Errorf("expected NoScan default to be false, got %v", settings.NoScan)
	}

	// other scan flags should default to false
	if settings.Dorking != false {
		t.Errorf("expected Dorking default to be false, got %v", settings.Dorking)
	}
	if settings.Git != false {
		t.Errorf("expected Git default to be false, got %v", settings.Git)
	}
	if settings.Nuclei != false {
		t.Errorf("expected Nuclei default to be false, got %v", settings.Nuclei)
	}
	if settings.JavaScript != false {
		t.Errorf("expected JavaScript default to be false, got %v", settings.JavaScript)
	}
	if settings.CMS != false {
		t.Errorf("expected CMS default to be false, got %v", settings.CMS)
	}
	if settings.Headers != false {
		t.Errorf("expected Headers default to be false, got %v", settings.Headers)
	}
	if settings.CloudStorage != false {
		t.Errorf("expected CloudStorage default to be false, got %v", settings.CloudStorage)
	}
	if settings.SubdomainTakeover != false {
		t.Errorf("expected SubdomainTakeover default to be false, got %v", settings.SubdomainTakeover)
	}

	// enum settings should default to empty string
	if settings.Dirlist != "" {
		t.Errorf("expected Dirlist default to be empty, got %v", settings.Dirlist)
	}
	if settings.Dnslist != "" {
		t.Errorf("expected Dnslist default to be empty, got %v", settings.Dnslist)
	}
	if settings.Ports != "" {
		t.Errorf("expected Ports default to be empty, got %v", settings.Ports)
	}
}

func TestSettingsNoScanBehavior(t *testing.T) {
	tests := []struct {
		name           string
		noScan         bool
		shouldBaseScan bool
	}{
		{
			name:           "default - base scan should run",
			noScan:         false,
			shouldBaseScan: true,
		},
		{
			name:           "noscan enabled - base scan should not run",
			noScan:         true,
			shouldBaseScan: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := &Settings{NoScan: tt.noScan}

			// the condition in sif.go is: if !app.settings.NoScan { scan.Scan(...) }
			shouldRun := !settings.NoScan
			if shouldRun != tt.shouldBaseScan {
				t.Errorf("expected shouldBaseScan=%v, got %v", tt.shouldBaseScan, shouldRun)
			}
		})
	}
}

func TestSettingsTimeoutDefault(t *testing.T) {
	settings := &Settings{}

	// timeout defaults to zero value, actual default (10s) is set in Parse()
	if settings.Timeout != 0 {
		t.Errorf("expected Timeout zero value, got %v", settings.Timeout)
	}
}

func TestSettingsThreadsDefault(t *testing.T) {
	settings := &Settings{}

	// threads defaults to zero value, actual default (10) is set in Parse()
	if settings.Threads != 0 {
		t.Errorf("expected Threads zero value, got %v", settings.Threads)
	}
}

func TestSettingsWithValues(t *testing.T) {
	settings := &Settings{
		NoScan:            true,
		Dorking:           true,
		Git:               true,
		Nuclei:            true,
		JavaScript:        true,
		CMS:               true,
		Headers:           true,
		CloudStorage:      true,
		SubdomainTakeover: true,
		Dirlist:           "medium",
		Dnslist:           "large",
		Ports:             "common",
		Timeout:           30 * time.Second,
		Threads:           20,
		Debug:             true,
		LogDir:            "/tmp/logs",
		ApiMode:           true,
	}

	if !settings.NoScan {
		t.Error("expected NoScan to be true")
	}
	if !settings.Dorking {
		t.Error("expected Dorking to be true")
	}
	if settings.Dirlist != "medium" {
		t.Errorf("expected Dirlist 'medium', got '%s'", settings.Dirlist)
	}
	if settings.Dnslist != "large" {
		t.Errorf("expected Dnslist 'large', got '%s'", settings.Dnslist)
	}
	if settings.Ports != "common" {
		t.Errorf("expected Ports 'common', got '%s'", settings.Ports)
	}
	if settings.Timeout != 30*time.Second {
		t.Errorf("expected Timeout 30s, got %v", settings.Timeout)
	}
	if settings.Threads != 20 {
		t.Errorf("expected Threads 20, got %d", settings.Threads)
	}
}
