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

import (
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/govaluate"
)

// maxDSLExprLen bounds a single dsl expression. govaluate's Evaluate takes no
// context and cannot be interrupted mid-helper, so capping the input is the
// reliable defense against a pathological expression.
const maxDSLExprLen = 4096

// allowedDSLHelpers is the set of helper functions a dsl expression may call,
// keyed by the underscore-stripped name so both alias forms (to_lower and
// tolower) resolve. It is an allowlist so a future projectdiscovery/dsl bump
// cannot silently reintroduce a side-effecting helper (llm_prompt, public_ip,
// wait_for, the gadget generators) or an unbounded-allocation one (repeat, the
// rand_* and faker families): anything unnamed here fails to compile.
var allowedDSLHelpers = func() map[string]bool {
	names := []string{
		// string inspection / comparison
		"contains", "contains_all", "contains_any", "starts_with", "ends_with",
		"line_starts_with", "line_ends_with", "equals_any", "len", "index",
		// string transforms
		"to_lower", "to_upper", "trim", "trim_left", "trim_right", "trim_space",
		"trim_prefix", "trim_suffix", "split", "join", "replace", "replace_regex",
		"concat", "reverse",
		// regex (RE2, linear-time)
		"regex", "regex_all", "regex_any",
		// encode / decode
		"base64", "base64_decode", "hex_encode", "hex_decode",
		"url_encode", "url_decode", "html_escape", "html_unescape",
		// hashing / fingerprint
		"md5", "sha1", "sha256", "mmh3",
		// numeric / conversion
		"to_number", "to_string",
	}
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[stripUnderscore(n)] = true
	}
	return m
}()

func stripUnderscore(s string) string { return strings.ReplaceAll(s, "_", "") }

// dslHelpers is the curated govaluate function map: every entry of
// dsl.HelperFunctions() whose (underscore-stripped) name is allowlisted.
var dslHelpers = func() map[string]govaluate.ExpressionFunction {
	all := dsl.HelperFunctions()
	out := make(map[string]govaluate.ExpressionFunction, len(all))
	for name, fn := range all {
		if allowedDSLHelpers[stripUnderscore(name)] {
			out[name] = fn
		}
	}
	return out
}()

// dslCache memoizes compiled expressions by source string. A compiled
// *EvaluableExpression is safe to Evaluate concurrently (value receiver, pooled
// scratch state), so sharing one across goroutines is fine.
var dslCache sync.Map // string -> *govaluate.EvaluableExpression

// hasNonEmptyDSL reports whether exprs holds at least one non-empty expression.
func hasNonEmptyDSL(exprs []string) bool {
	for _, e := range exprs {
		if strings.TrimSpace(e) != "" {
			return true
		}
	}
	return false
}

// dslCompile compiles expr against the curated helpers, caching the result, so
// an over-length expression, a syntax error or a non-allowlisted function is
// rejected at module load rather than silently missing at match time.
func dslCompile(expr string) (*govaluate.EvaluableExpression, error) {
	if len(expr) > maxDSLExprLen {
		return nil, fmt.Errorf("dsl expression exceeds %d bytes", maxDSLExprLen)
	}
	if cached, ok := dslCache.Load(expr); ok {
		return cached.(*govaluate.EvaluableExpression), nil
	}
	compiled, err := govaluate.NewEvaluableExpressionWithFunctions(expr, dslHelpers)
	if err != nil {
		return nil, fmt.Errorf("dsl expression %q: %w", expr, err)
	}
	actual, _ := dslCache.LoadOrStore(expr, compiled)
	return actual.(*govaluate.EvaluableExpression), nil
}
