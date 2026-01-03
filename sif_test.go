/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (vmfunc), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package sif

import (
	"testing"

	"github.com/dropalldatabases/sif/pkg/config"
)

// mockResult is a test implementation of ScanResult
type mockResult struct {
	name string
	data string
}

func (m *mockResult) ResultType() string {
	return m.name
}

func TestNewModuleResult(t *testing.T) {
	tests := []struct {
		name   string
		result *mockResult
		wantID string
	}{
		{
			name:   "basic result",
			result: &mockResult{name: "test", data: "test data"},
			wantID: "test",
		},
		{
			name:   "empty name",
			result: &mockResult{name: "", data: "data"},
			wantID: "",
		},
		{
			name:   "complex name",
			result: &mockResult{name: "framework-detection", data: "Laravel 8.0"},
			wantID: "framework-detection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr := NewModuleResult(tt.result)
			if mr.Id != tt.wantID {
				t.Errorf("NewModuleResult() Id = %q, want %q", mr.Id, tt.wantID)
			}
			if mr.Data != tt.result {
				t.Errorf("NewModuleResult() Data = %v, want %v", mr.Data, tt.result)
			}
		})
	}
}

func TestNew_NoTargets(t *testing.T) {
	settings := &config.Settings{
		URLs: []string{},
		File: "",
	}

	_, err := New(settings)
	if err == nil {
		t.Error("New() should return error when no targets provided")
	}
}

func TestNew_WithURLs(t *testing.T) {
	settings := &config.Settings{
		URLs:    []string{"https://example.com"},
		ApiMode: true,
	}

	app, err := New(settings)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	if app == nil {
		t.Fatal("New() returned nil app")
	}

	if len(app.targets) != 1 {
		t.Errorf("New() targets = %d, want 1", len(app.targets))
	}

	if app.targets[0] != "https://example.com" {
		t.Errorf("New() target = %q, want %q", app.targets[0], "https://example.com")
	}
}

func TestNew_URLValidation(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid https url",
			url:     "https://example.com",
			wantErr: false,
		},
		{
			name:    "valid http url",
			url:     "http://example.com",
			wantErr: false,
		},
		{
			name:    "missing protocol",
			url:     "example.com",
			wantErr: true,
		},
		{
			name:    "invalid protocol",
			url:     "ftp://example.com",
			wantErr: true,
		},
		{
			name:    "empty url",
			url:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := &config.Settings{
				URLs:    []string{tt.url},
				ApiMode: true,
			}

			_, err := New(settings)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestModuleResult_JSON(t *testing.T) {
	mr := ModuleResult{
		Id:   "test",
		Data: map[string]string{"key": "value"},
	}

	// Verify the struct can be used (basic sanity check)
	if mr.Id != "test" {
		t.Errorf("ModuleResult.Id = %q, want %q", mr.Id, "test")
	}
}

func TestUrlResult_JSON(t *testing.T) {
	ur := UrlResult{
		Url: "https://example.com",
		Results: []ModuleResult{
			{Id: "test", Data: "data"},
		},
	}

	if ur.Url != "https://example.com" {
		t.Errorf("UrlResult.Url = %q, want %q", ur.Url, "https://example.com")
	}

	if len(ur.Results) != 1 {
		t.Errorf("UrlResult.Results = %d, want 1", len(ur.Results))
	}
}
