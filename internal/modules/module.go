/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2026 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

// Package modules provides the module system infrastructure for SIF.
// It defines the core interfaces, types, and utilities for building
// and executing security scanning modules.
package modules

import (
	"context"
	"net/http"
	"time"
)

// ModuleType represents the type of module.
type ModuleType string

const (
	TypeHTTP   ModuleType = "http"
	TypeDNS    ModuleType = "dns"
	TypeTCP    ModuleType = "tcp"
	TypeScript ModuleType = "script"
)

// Module is the interface all modules implement.
// Each module must provide metadata, specify its type, and implement
// an Execute method for running the scan against a target.
type Module interface {
	// Info returns the module metadata.
	Info() Info

	// Type returns the module type (http, dns, tcp, script).
	Type() ModuleType

	// Execute runs the module against the specified target.
	Execute(ctx context.Context, target string, opts Options) (*Result, error)
}

// Info contains module metadata.
type Info struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Author      string   `yaml:"author" json:"author"`
	Severity    string   `yaml:"severity" json:"severity"`
	Description string   `yaml:"description" json:"description"`
	Tags        []string `yaml:"tags" json:"tags"`
}

// Options for module execution.
type Options struct {
	Timeout time.Duration
	Threads int
	LogDir  string
	Client  *http.Client
}

// Result from module execution.
type Result struct {
	ModuleID string    `json:"module_id"`
	Target   string    `json:"target"`
	Findings []Finding `json:"findings,omitempty"`
}

// ResultType implements the ScanResult interface from pkg/scan.
func (r *Result) ResultType() string {
	return r.ModuleID
}

// Finding represents a discovered issue.
type Finding struct {
	URL       string            `json:"url,omitempty"`
	Severity  string            `json:"severity"`
	Evidence  string            `json:"evidence,omitempty"`
	Extracted map[string]string `json:"extracted,omitempty"`
}

// Matcher defines matching logic for module responses.
// Matchers are used to determine if a response indicates a vulnerability.
type Matcher struct {
	Type      string   `yaml:"type"` // regex, status, word, favicon, size, range
	Part      string   `yaml:"part"` // body, header, all
	Regex     []string `yaml:"regex,omitempty"`
	Words     []string `yaml:"words,omitempty"`
	Status    []int    `yaml:"status,omitempty"`
	Size      []int    `yaml:"size,omitempty"`
	Hash      []int64  `yaml:"hash,omitempty"` // favicon: shodan mmh3 hashes (signed or unsigned)
	Condition string   `yaml:"condition"`      // and, or
	Negative  bool     `yaml:"negative"`

	// Source selects the numeric value a range matcher tests: size (default,
	// response/banner byte length) or status (http status code). range only.
	Source string `yaml:"source,omitempty"`
	// Min and Max are the inclusive bounds of a range matcher. A nil bound is
	// unbounded on that side; at least one must be set. range only.
	Min *int `yaml:"min,omitempty"`
	Max *int `yaml:"max,omitempty"`
	// CaseInsensitive folds word matching to lower-case when set (word matcher only).
	CaseInsensitive bool `yaml:"case-insensitive,omitempty"`
}

// Extractor defines data extraction from responses.
// Extractors pull specific data from matched responses for reporting.
type Extractor struct {
	Type  string   `yaml:"type"` // regex, kv, json
	Name  string   `yaml:"name"`
	Part  string   `yaml:"part"`
	Regex []string `yaml:"regex,omitempty"`
	JSON  []string `yaml:"json,omitempty"`
	Group int      `yaml:"group"`
}
