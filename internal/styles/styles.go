/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (Celeste Hickenlooper), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

// Package styles provides custom styling options for the SIF tool's console output.
// This package re-exports styles from internal/output for backwards compatibility.
package styles

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/vmfunc/sif/internal/output"
)

// Re-export styles from output package
var (
	Status     = output.Status
	Highlight  = output.Highlight
	Box        = output.Box
	Subheading = output.Subheading
)

// Separator style - kept for backwards compatibility but deprecated
// Use output.ScanStart() instead
var Separator = lipgloss.NewStyle().
	Border(lipgloss.ThickBorder(), true, false).
	Bold(true)

// Severity level styles - re-exported from output
var (
	SeverityLow      = output.SeverityLow
	SeverityMedium   = output.SeverityMedium
	SeverityHigh     = output.SeverityHigh
	SeverityCritical = output.SeverityCritical
)
