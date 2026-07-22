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

import "encoding/json"

// reportFinding is the stable json shape for a finding in the -json report. it's
// a dedicated view, not the Finding struct itself, so severity renders as its
// string name and the on-disk snapshot format (which marshals Finding directly)
// stays untouched. confidence is omitted when zero so recon findings without a
// detection score don't carry a misleading 0.
type reportFinding struct {
	Target     string  `json:"target"`
	Module     string  `json:"module"`
	Severity   string  `json:"severity"`
	Key        string  `json:"key"`
	Title      string  `json:"title"`
	Evidence   string  `json:"evidence,omitempty"`
	Confidence float32 `json:"confidence,omitempty"`
}

// JSONReport serializes a run's normalized findings to an indented json array.
// it never returns a nil body: an empty run marshals to "[]" so consumers can
// always parse the output.
func JSONReport(findings []Finding) ([]byte, error) {
	out := make([]reportFinding, 0, len(findings))
	for i := 0; i < len(findings); i++ {
		f := findings[i]
		out = append(out, reportFinding{
			Target:     f.Target,
			Module:     f.Module,
			Severity:   f.Severity.String(),
			Key:        f.Key,
			Title:      f.Title,
			Evidence:   f.Raw,
			Confidence: f.Confidence,
		})
	}
	return json.MarshalIndent(out, "", "  ")
}
