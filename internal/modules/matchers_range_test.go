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

package modules

import "testing"

func TestInRange(t *testing.T) {
	intp := func(n int) *int { return &n }

	tests := []struct {
		name string
		v    int
		min  *int
		max  *int
		want bool
	}{
		{name: "within both bounds", v: 50, min: intp(10), max: intp(100), want: true},
		{name: "below min", v: 5, min: intp(10), max: intp(100), want: false},
		{name: "above max", v: 101, min: intp(10), max: intp(100), want: false},
		{name: "at min inclusive", v: 10, min: intp(10), max: intp(100), want: true},
		{name: "at max inclusive", v: 100, min: intp(10), max: intp(100), want: true},
		{name: "min only, above", v: 1000, min: intp(10), max: nil, want: true},
		{name: "min only, below", v: 5, min: intp(10), max: nil, want: false},
		{name: "max only, below", v: 5, min: nil, max: intp(100), want: true},
		{name: "max only, above", v: 1000, min: nil, max: intp(100), want: false},
		{name: "both nil is vacuously true", v: 12345, min: nil, max: nil, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inRange(tt.v, tt.min, tt.max); got != tt.want {
				t.Errorf("inRange(%d) = %v, want %v", tt.v, got, tt.want)
			}
		})
	}
}

func TestCheckMatcherRange(t *testing.T) {
	intp := func(n int) *int { return &n }

	t.Run("status source in range", func(t *testing.T) {
		resp := fakeResponse(t, 503, nil)
		m := &Matcher{Type: "range", Source: "status", Min: intp(500), Max: intp(599)}
		if !checkMatcher(m, resp, "") {
			t.Error("expected 503 to be within 500-599")
		}
	})

	t.Run("status source out of range", func(t *testing.T) {
		resp := fakeResponse(t, 200, nil)
		m := &Matcher{Type: "range", Source: "status", Min: intp(500), Max: intp(599)}
		if checkMatcher(m, resp, "") {
			t.Error("expected 200 to be outside 500-599")
		}
	})

	t.Run("size source default", func(t *testing.T) {
		resp := fakeResponse(t, 200, nil)
		m := &Matcher{Type: "range", Min: intp(5), Max: intp(20)}
		if !checkMatcher(m, resp, "twelve chars") {
			t.Error("expected body length within bounds to match")
		}
	})

	t.Run("size source explicit", func(t *testing.T) {
		resp := fakeResponse(t, 200, nil)
		m := &Matcher{Type: "range", Source: "size", Min: intp(1000)}
		if checkMatcher(m, resp, "short") {
			t.Error("expected short body to miss a high min bound")
		}
	})
}

// TestParseYAMLModuleMatcherRangeFields confirms yaml.v3 unmarshals the range
// matcher's scalars into *int (allocating on presence, nil on absence).
func TestParseYAMLModuleMatcherRangeFields(t *testing.T) {
	const doc = `id: new-fields
type: http
info:
  severity: info
http:
  method: GET
  paths: ["{{BaseURL}}/"]
  matchers:
    - type: range
      source: status
      min: 200
      max: 299
`
	dir := t.TempDir()
	path := writeModule(t, dir, "new-fields.yaml", doc)
	def, err := ParseYAMLModule(path)
	if err != nil {
		t.Fatalf("ParseYAMLModule: %v", err)
	}
	if len(def.HTTP.Matchers) != 1 {
		t.Fatalf("got %d matchers, want 1", len(def.HTTP.Matchers))
	}

	rng := def.HTTP.Matchers[0]
	if rng.Source != "status" {
		t.Errorf("Source = %q, want status", rng.Source)
	}
	if rng.Min == nil || *rng.Min != 200 {
		t.Fatalf("Min = %v, want *200", rng.Min)
	}
	if rng.Max == nil || *rng.Max != 299 {
		t.Fatalf("Max = %v, want *299", rng.Max)
	}
}

func TestParseYAMLModuleMatcherRangeValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string { return writeModule(t, dir, name, body) }

	rangeNoBounds := write("range-no-bounds.yaml", "id: rnb\ntype: http\nhttp:\n  paths: [\"/\"]\n  matchers:\n    - type: range\n")
	if _, err := ParseYAMLModule(rangeNoBounds); err == nil {
		t.Fatal("range matcher with no bounds accepted")
	}

	rangeMinMax := write("range-min-max.yaml", "id: rmm\ntype: http\nhttp:\n  paths: [\"/\"]\n  matchers:\n    - type: range\n      min: 100\n      max: 1\n")
	if _, err := ParseYAMLModule(rangeMinMax); err == nil {
		t.Fatal("range matcher with min>max accepted")
	}

	rangeBadSource := write("range-bad-source.yaml", "id: rbs\ntype: http\nhttp:\n  paths: [\"/\"]\n  matchers:\n    - type: range\n      source: bogus\n      min: 1\n")
	if _, err := ParseYAMLModule(rangeBadSource); err == nil {
		t.Fatal("range matcher with bad source accepted")
	}

	rangeOK := write("range-ok.yaml", "id: rok\ntype: http\nhttp:\n  paths: [\"/\"]\n  matchers:\n    - type: range\n      source: size\n      min: 0\n      max: 1000\n")
	if _, err := ParseYAMLModule(rangeOK); err != nil {
		t.Fatalf("valid range matcher rejected: %v", err)
	}
}
