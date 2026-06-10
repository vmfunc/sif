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
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// Markdown renders results as a readable report grouped by target, then by
// module, with each module's finding pretty-printed as a json code block.
func Markdown(results []Result) []byte {
	var b strings.Builder
	b.WriteString("# sif scan report\n\n")

	// group module results under their target so the report reads target-first
	// regardless of the order results came in.
	byTarget := make(map[string][]Result)
	order := make([]string, 0)
	for i := 0; i < len(results); i++ {
		t := results[i].Target
		if _, seen := byTarget[t]; !seen {
			order = append(order, t)
		}
		byTarget[t] = append(byTarget[t], results[i])
	}

	for i := 0; i < len(order); i++ {
		target := order[i]
		b.WriteString("## ")
		b.WriteString(target)
		b.WriteString("\n\n")

		mods := byTarget[target]
		// sort modules so the report is deterministic across runs
		sort.SliceStable(mods, func(a, c int) bool { return mods[a].Module < mods[c].Module })

		for j := 0; j < len(mods); j++ {
			b.WriteString("### ")
			b.WriteString(mods[j].Module)
			b.WriteString("\n\n")
			b.WriteString("```json\n")
			b.WriteString(prettyJSON(mods[j].Data))
			b.WriteString("\n```\n\n")
		}
	}

	return []byte(b.String())
}

// prettyJSON re-indents the raw finding for readability; if it doesn't parse as
// json (shouldn't happen, but never trust it) the raw bytes are returned as-is.
func prettyJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "null"
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, raw, "", "  "); err != nil {
		return string(raw)
	}
	return indented.String()
}
