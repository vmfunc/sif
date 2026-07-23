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

/*
-------------------------------------------------------------------------------------------------
:                                                                               :
:   SIF   -   Blazing-fast pentesting suite                                :
:   Blaze    -   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2026 vmfunc, xyzeva,                                               :
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
	Method            string            `yaml:"method"`
	Paths             []string          `yaml:"paths"`
	Wordlist          string            `yaml:"wordlist,omitempty"`
	Payloads          []string          `yaml:"payloads,omitempty"`
	Headers           map[string]string `yaml:"headers,omitempty"`
	Body              string            `yaml:"body,omitempty"`
	Attack            string            `yaml:"attack,omitempty"` // clusterbomb (default), pitchfork
	Threads           int               `yaml:"threads,omitempty"`
	DisableRedirects  bool              `yaml:"disable-redirects,omitempty"` // stop at the first response; don't follow 3xx
	Matchers          []Matcher         `yaml:"matchers"`
	MatchersCondition string            `yaml:"matchers-condition,omitempty"` // and (default), or
	Extractors        []Extractor       `yaml:"extractors,omitempty"`
	Requests          []HTTPStep        `yaml:"requests,omitempty"` // ordered request chain; see HTTPStep
}

// HTTPStep is one request in a chain. steps run in order and share a variable
// map: each step's extractors populate {{name}} references usable in the path,
// headers and body of later steps. a step whose matchers don't match halts the
// chain, so a login step can gate an authenticated follow-up request. when
// HTTPConfig.Requests is empty the single-request fields above drive the module
// unchanged.
type HTTPStep struct {
	Name              string            `yaml:"name,omitempty"`
	Method            string            `yaml:"method,omitempty"`
	Path              string            `yaml:"path"`
	Headers           map[string]string `yaml:"headers,omitempty"`
	Body              string            `yaml:"body,omitempty"`
	Matchers          []Matcher         `yaml:"matchers,omitempty"`
	MatchersCondition string            `yaml:"matchers-condition,omitempty"`
	Extractors        []Extractor       `yaml:"extractors,omitempty"`
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
	Port              int         `yaml:"port"`
	Data              string      `yaml:"data,omitempty"`
	Matchers          []Matcher   `yaml:"matchers"`
	MatchersCondition string      `yaml:"matchers-condition,omitempty"` // and (default), or
	Extractors        []Extractor `yaml:"extractors,omitempty"`
}

// ParseYAMLModule parses a YAML file into a module definition
func ParseYAMLModule(path string) (*YAMLModule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read module file: %w", err)
	}
	return ParseYAMLModuleBytes(data)
}

// ParseYAMLModuleBytes parses and validates a module definition from raw bytes,
// so the loader can read modules from an embedded fs.FS as well as from disk.
func ParseYAMLModuleBytes(data []byte) (*YAMLModule, error) {
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

	if ym.HTTP != nil {
		if err := validateAttack(ym.HTTP.Attack); err != nil {
			return nil, fmt.Errorf("module %q: %w", ym.ID, err)
		}
		if err := validateMatchersCondition(ym.HTTP.MatchersCondition); err != nil {
			return nil, fmt.Errorf("module %q: %w", ym.ID, err)
		}
		for i := range ym.HTTP.Requests {
			step := &ym.HTTP.Requests[i]
			if step.Path == "" {
				return nil, fmt.Errorf("module %q: request %d missing required field: path", ym.ID, i)
			}
			if err := validateMatchersCondition(step.MatchersCondition); err != nil {
				return nil, fmt.Errorf("module %q request %d: %w", ym.ID, i, err)
			}
			if err := validateMatchers(step.Matchers); err != nil {
				return nil, fmt.Errorf("module %q request %d: %w", ym.ID, i, err)
			}
		}
	}
	if ym.TCP != nil {
		if err := validateTCP(ym.TCP); err != nil {
			return nil, fmt.Errorf("module %q: %w", ym.ID, err)
		}
	}
	if ym.DNS != nil {
		if err := validateDNS(ym.DNS); err != nil {
			return nil, fmt.Errorf("module %q: %w", ym.ID, err)
		}
	}
	var matchers []Matcher
	switch {
	case ym.HTTP != nil:
		matchers = ym.HTTP.Matchers
	case ym.DNS != nil:
		matchers = ym.DNS.Matchers
	case ym.TCP != nil:
		matchers = ym.TCP.Matchers
	}
	if err := validateMatchers(matchers); err != nil {
		return nil, fmt.Errorf("module %q: %w", ym.ID, err)
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
