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
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/govaluate"
	nucleiutils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
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

// dslVars builds the variable environment a dsl expression evaluates against,
// using nuclei's lowercase names so nuclei dsl expressions paste in unchanged.
// Named extractor values overlay the builtins (matching nuclei's mutation
// order), so an extractor may reference, and on a name clash shadow, a builtin.
func dslVars(mc *MatchContext) map[string]interface{} {
	headers := getPart("header", mc.Resp, mc.Body)
	vars := map[string]interface{}{
		"status_code":    statusCodeOf(mc.Resp),
		"body":           mc.Body,
		"content_length": len(mc.Body),
		"all_headers":    headers,
		"header":         headers,
		"duration":       mc.Duration.Seconds(),
		"host":           hostOf(mc.URL),
	}
	// non-http builtins, such as ssl's expired/self_signed, sit at the same tier
	// as the vars above, so a named extractor can shadow one deliberately.
	for k, v := range mc.Extra {
		vars[k] = v
	}
	// the capitalized nuclei url-part vars, plus the dns ones. nuclei's own
	// generator keeps them faithful: Host is the hostname without port while
	// Hostname carries it, Path is the directory, Port defaults by scheme.
	for k, v := range nucleiutils.GenerateVariables(mc.URL, false, nil) {
		vars[k] = v
	}
	for k, v := range mc.Extracted {
		vars[k] = v
	}
	return vars
}

// hostOf returns the host[:port] of a request URL, matching nuclei's `host`
// variable so a pasted nuclei expression (host == "example.com") behaves as
// expected. On an unparseable URL it falls back to the raw string rather than
// binding an empty host.
func hostOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return u.Host
	}
	return rawURL
}

func statusCodeOf(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

// evalDSL folds a dsl matcher's expressions under its condition (default AND).
// An expression that errors at eval, or yields a non-bool, counts as false
// (fail-closed), matching the engine's swallow-at-match-time invariant.
func evalDSL(m *Matcher, mc *MatchContext) bool {
	if len(m.DSL) == 0 {
		return false
	}
	vars := dslVars(mc)
	or := strings.EqualFold(m.Condition, "or")
	for _, expr := range m.DSL {
		matched := evalOneDSL(expr, vars)
		if or && matched {
			return true
		}
		if !or && !matched {
			return false
		}
	}
	return !or
}

func evalOneDSL(expr string, vars map[string]interface{}) bool {
	compiled, err := dslCompile(expr)
	if err != nil {
		return false // unreachable after load validation; fail closed anyway
	}
	result, err := compiled.Evaluate(vars)
	if err != nil {
		return false // unbound var / type mismatch -> miss
	}
	b, ok := result.(bool)
	return ok && b
}
