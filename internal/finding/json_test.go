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

import (
	"encoding/json"
	"testing"
)

func TestJSONReportEmptyIsArray(t *testing.T) {
	data, err := JSONReport(nil)
	if err != nil {
		t.Fatalf("JSONReport: %v", err)
	}
	if string(data) != "[]" {
		t.Errorf("empty report = %q, want %q", string(data), "[]")
	}
}

func TestJSONReportShapeAndFields(t *testing.T) {
	findings := []Finding{
		{Target: "https://x", Module: "framework", Severity: SeverityHigh, Key: "framework:Laravel", Title: "Laravel detected", Raw: "Laravel 9.0", Confidence: 0.82},
		{Target: "https://x", Module: "headers", Severity: SeverityInfo, Key: "headers:Server", Title: "Server", Raw: "nginx"},
	}
	data, err := JSONReport(findings)
	if err != nil {
		t.Fatalf("JSONReport: %v", err)
	}

	var got []map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("report is not valid json: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}

	// framework finding: severity rendered as its string name, confidence present.
	if got[0]["severity"] != "high" {
		t.Errorf("severity = %v, want \"high\"", got[0]["severity"])
	}
	if got[0]["confidence"] != 0.82 {
		t.Errorf("confidence = %v, want 0.82", got[0]["confidence"])
	}

	// recon finding: zero confidence is omitted rather than serialized as 0.
	if _, ok := got[1]["confidence"]; ok {
		t.Errorf("zero confidence should be omitted, got %v", got[1]["confidence"])
	}
	if got[1]["severity"] != "info" {
		t.Errorf("severity = %v, want \"info\"", got[1]["severity"])
	}
}
