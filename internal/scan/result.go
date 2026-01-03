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

package scan

// Named slice types for scan results.
// These provide better type safety and allow method implementations.
type (
	HeaderResults            []HeaderResult
	DirectoryResults         []DirectoryResult
	CloudStorageResults      []CloudStorageResult
	DorkResults              []DorkResult
	SubdomainTakeoverResults []SubdomainTakeoverResult
)

// ScanResult is the interface that all scan result types implement.
// This enables type-safe handling of heterogeneous scan results.
type ScanResult interface {
	// ResultType returns the unique identifier for this result type.
	ResultType() string
}

// ResultType implementations for pointer result types.

func (r *ShodanResult) ResultType() string { return "shodan" }
func (r *SQLResult) ResultType() string    { return "sql" }
func (r *LFIResult) ResultType() string    { return "lfi" }
func (r *CMSResult) ResultType() string    { return "cms" }

// ResultType implementations for slice result types.

func (r HeaderResults) ResultType() string            { return "headers" }
func (r DirectoryResults) ResultType() string         { return "dirlist" }
func (r CloudStorageResults) ResultType() string      { return "cloudstorage" }
func (r DorkResults) ResultType() string              { return "dork" }
func (r SubdomainTakeoverResults) ResultType() string { return "subdomain_takeover" }

// Compile-time interface satisfaction checks.
var (
	_ ScanResult = (*ShodanResult)(nil)
	_ ScanResult = (*SQLResult)(nil)
	_ ScanResult = (*LFIResult)(nil)
	_ ScanResult = (*CMSResult)(nil)
	_ ScanResult = HeaderResults(nil)
	_ ScanResult = DirectoryResults(nil)
	_ ScanResult = CloudStorageResults(nil)
	_ ScanResult = DorkResults(nil)
	_ ScanResult = SubdomainTakeoverResults(nil)
)
