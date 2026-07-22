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

// Package report serializes collected scan results to sarif and markdown. it's
// deliberately decoupled from the scan package: callers map their own results
// into report.Result, so report never imports a scanner type.
package report

import "encoding/json"

// Result is one module's output for one target. Data is whatever the scanner
// returned, carried as raw json so report stays free of scan types. Severity is
// the normalized rank ("critical".."info", or "" when the source carries none),
// passed in as a plain string so report keeps its independence from the finding
// package; the sarif writer maps it onto a sarif level.
type Result struct {
	Target   string
	Module   string
	Severity string
	Data     json.RawMessage
}
