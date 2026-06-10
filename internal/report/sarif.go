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

package report

import (
	"encoding/json"
	"fmt"
)

// sarif format/version constants pinned to the 2.1.0 schema so the output is
// ingestable by github code scanning and other sarif consumers.
const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	toolName     = "sif"
)

// sarifLog is the minimal valid 2.1.0 shape: one run from one tool.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID string `json:"id"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// sarifLevel is the default severity for findings; sif results don't carry a
// uniform severity field, so "warning" is the neutral middle ground.
const sarifLevel = "warning"

// SARIF serializes results to a minimal valid sarif 2.1.0 log. Each module
// result becomes one sarif result tagged with its module id (the rule) and the
// target uri, with the raw module data inlined into the message for context.
func SARIF(results []Result) ([]byte, error) {
	sarifResults := make([]sarifResult, 0, len(results))
	ruleSet := make(map[string]struct{}, len(results))

	for i := 0; i < len(results); i++ {
		res := results[i]
		ruleSet[res.Module] = struct{}{}

		sarifResults = append(sarifResults, sarifResult{
			RuleID:  res.Module,
			Level:   sarifLevel,
			Message: sarifMessage{Text: messageFor(res)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: res.Target},
				},
			}},
		})
	}

	// rules must list each id exactly once; build it from the set so duplicate
	// modules across targets don't duplicate the rule.
	rules := make([]sarifRule, 0, len(ruleSet))
	for id := range ruleSet {
		rules = append(rules, sarifRule{ID: id})
	}

	doc := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: toolName, Rules: rules}},
			Results: sarifResults,
		}},
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal sarif: %w", err)
	}
	return out, nil
}

// messageFor builds a human-readable result message: the module id plus the raw
// finding json so a sarif viewer shows what was actually found.
func messageFor(res Result) string {
	if len(res.Data) == 0 {
		return fmt.Sprintf("%s finding on %s", res.Module, res.Target)
	}
	return fmt.Sprintf("%s finding on %s: %s", res.Module, res.Target, string(res.Data))
}
