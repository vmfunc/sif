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

package finding

import "strings"

// Severity is an ordered severity rank shared by every normalized finding.
// the order matters: notify gates on a threshold and diff sorts by it, so the
// underlying ints have to compare info < low < medium < high < critical.
type Severity int

// severity ranks, lowest to highest. SeverityUnknown sorts below everything so
// an unrecognized scanner string never silently outranks a real critical.
const (
	SeverityUnknown Severity = iota
	SeverityInfo
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// severityNames maps each rank to its canonical lowercase string. the wire
// format scanners emit ("info"/"low"/...) round-trips through this table.
var severityNames = map[Severity]string{
	SeverityUnknown:  "unknown",
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

// String renders the canonical lowercase name for the rank.
func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return severityNames[SeverityUnknown]
}

// ParseSeverity maps a scanner's free-form severity string onto a rank. it's
// case/space insensitive and folds the common synonyms ("informational",
// "warning", "moderate") so the dozen scanners that each picked their own
// spelling all land on the same ladder. an empty or unrecognized value is
// SeverityUnknown rather than a guess.
func ParseSeverity(raw string) Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "moderate", "warning":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info", "informational", "information", "none":
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// AtLeast reports whether s is at or above threshold; notify uses it to drop
// findings below the configured floor.
func (s Severity) AtLeast(threshold Severity) bool {
	return s >= threshold
}
