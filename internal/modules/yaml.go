/*
-------------------------------------------------------------------------------------------------
:                                                                               :
:   SIF   -   Blazing-fast pentesting suite                                :
:   Blaze    -   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (vmfunc), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
-------------------------------------------------------------------------------------------------
*/

package modules

import (
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// YAMLModule represents a parsed YAML module file
type YAMLModule struct {
	ID   string         `yaml:"id"`
	Info YAMLModuleInfo `yaml:"info"`
	Type ModuleType     `yaml:"type"`
	HTTP *HTTPConfig    `yaml:"http,omitempty"`
	DNS  *DNSConfig     `yaml:"dns,omitempty"`
	TCP  *TCPConfig     `yaml:"tcp,omitempty"`
}

// YAMLModuleInfo contains module metadata
type YAMLModuleInfo struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
}

// HTTPConfig defines HTTP module settings
type HTTPConfig struct {
	Method     string            `yaml:"method"`
	Paths      []string          `yaml:"paths"`
	Payloads   []string          `yaml:"payloads,omitempty"`
	Headers    map[string]string `yaml:"headers,omitempty"`
	Body       string            `yaml:"body,omitempty"`
	Attack     string            `yaml:"attack,omitempty"` // sniper, pitchfork, clusterbomb
	Threads    int               `yaml:"threads,omitempty"`
	Matchers   []Matcher         `yaml:"matchers"`
	Extractors []Extractor       `yaml:"extractors,omitempty"`
}

// DNSConfig defines DNS module settings
type DNSConfig struct {
	Type       string      `yaml:"type"` // A, AAAA, MX, TXT, NS, etc.
	Name       string      `yaml:"name"`
	Matchers   []Matcher   `yaml:"matchers"`
	Extractors []Extractor `yaml:"extractors,omitempty"`
}

// TCPConfig defines TCP module settings
type TCPConfig struct {
	Port       int         `yaml:"port"`
	Data       string      `yaml:"data,omitempty"`
	Matchers   []Matcher   `yaml:"matchers"`
	Extractors []Extractor `yaml:"extractors,omitempty"`
}

// ParseYAMLModule parses a YAML file into a module definition
func ParseYAMLModule(path string) (*YAMLModule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read module file: %w", err)
	}

	var ym YAMLModule
	if err := yaml.Unmarshal(data, &ym); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}

	if ym.ID == "" {
		return nil, fmt.Errorf("module missing required field: id")
	}

	if ym.Type == "" {
		return nil, fmt.Errorf("module missing required field: type")
	}

	return &ym, nil
}

// yamlModuleWrapper wraps YAMLModule to implement the Module interface
type yamlModuleWrapper struct {
	def  *YAMLModule
	path string
}

// newYAMLModuleWrapper creates a Module from a YAMLModule definition
func newYAMLModuleWrapper(def *YAMLModule, path string) *yamlModuleWrapper {
	return &yamlModuleWrapper{def: def, path: path}
}

// Info returns the module metadata
func (m *yamlModuleWrapper) Info() Info {
	return Info{
		ID:          m.def.ID,
		Name:        m.def.Info.Name,
		Author:      m.def.Info.Author,
		Severity:    m.def.Info.Severity,
		Description: m.def.Info.Description,
		Tags:        m.def.Info.Tags,
	}
}

// Type returns the module type
func (m *yamlModuleWrapper) Type() ModuleType {
	return m.def.Type
}

// Execute runs the module (delegates to appropriate executor)
func (m *yamlModuleWrapper) Execute(ctx context.Context, target string, opts Options) (*Result, error) {
	switch m.def.Type {
	case TypeHTTP:
		if m.def.HTTP == nil {
			return nil, fmt.Errorf("HTTP module missing http configuration")
		}
		return ExecuteHTTPModule(ctx, target, m.def, opts)
	case TypeDNS:
		if m.def.DNS == nil {
			return nil, fmt.Errorf("DNS module missing dns configuration")
		}
		return ExecuteDNSModule(ctx, target, m.def, opts)
	case TypeTCP:
		if m.def.TCP == nil {
			return nil, fmt.Errorf("TCP module missing tcp configuration")
		}
		return ExecuteTCPModule(ctx, target, m.def, opts)
	default:
		return nil, fmt.Errorf("unsupported module type: %s", m.def.Type)
	}
}
