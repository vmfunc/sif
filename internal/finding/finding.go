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

// Package finding is the one normalization layer between the scan results and
// the consumers that don't want to know about ~two dozen result structs: notify
// (later) gates and renders on it, diff (later) keys runs off it. Flatten is the
// single type-switch; adding a scanner without teaching Flatten about it trips
// the guard test in flatten_test.go, on purpose.
package finding

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/vmfunc/sif/internal/modules"
	"github.com/vmfunc/sif/internal/scan"
	"github.com/vmfunc/sif/internal/scan/frameworks"
	"github.com/vmfunc/sif/internal/scan/js"
)

// Finding is the normalized shape every scanner result collapses to. one
// Finding is one underlying item (a single header, one cors hit, one nuclei
// match) rather than a whole module's blob, so consumers diff and notify at
// item granularity.
type Finding struct {
	Target     string   // the url/host the scan ran against
	Module     string   // the ResultType() of the source scanner
	Severity   Severity // ranked severity, SeverityUnknown when the source has none
	Key        string   // stable identity for dedup/diff: module + ":" + identifier
	Title      string   // short human label
	Raw        string   // short evidence string, not the full body
	Confidence float32  // detection confidence 0..1; zero when the source has none
}

// Line renders a finding as one stable, terse, machine-friendly line for the
// -silent plain sink: "[severity] target module title". no styling, no color -
// a downstream pipe (notify, grep, awk) keys off the bracketed severity and the
// fixed field order, so the shape stays frozen. pointer receiver: Finding is
// wide enough that copying it per line is wasteful.
func (f *Finding) Line() string {
	return fmt.Sprintf("[%s] %s %s %s", f.Severity, f.Target, f.Module, f.Title)
}

// static per-module severities for results that carry no severity field of
// their own. these are the editorial baseline; a scanner that emits its own
// severity (cors, xss, nuclei, ...) overrides this on a per-item basis.
const (
	// a live admin panel / takeover / public bucket is high on its own.
	sevTakeover   = SeverityHigh
	sevPublicS3   = SeverityHigh
	sevAdminPanel = SeverityHigh
	// disclosure-grade signals: dberrors, secrets, supabase keys.
	sevDBError = SeverityMedium
	sevSecret  = SeverityMedium
	// pure recon/inventory: headers, crawl urls, passive hosts, ports.
	sevRecon = SeverityInfo
)

// keySep joins the module id and the per-item identifier into a Key. kept as a
// const so the diff layer can split on it without re-deriving the separator.
const keySep = ":"

// key builds a stable per-item identity: module:identifier. identifier is
// whatever uniquely names the item within its module (a url, a header name, a
// subdomain) so the same finding across two runs produces the same Key.
func key(module, identifier string) string {
	return module + keySep + identifier
}

// Flatten normalizes one module's result into zero or more Findings. result is
// the raw data carried in a ModuleResult; the type switch covers every scan
// result struct. an unrecognized type yields a single SeverityUnknown finding
// keyed "module:unhandled" so a new scanner surfaces loudly instead of
// vanishing - the guard test asserts this never happens for a known type.
func Flatten(target, module string, result any) []Finding {
	var out []Finding
	switch r := result.(type) {
	case *scan.ShodanResult:
		out = flattenShodan(target, r)
	case *scan.SQLResult:
		out = flattenSQL(target, r)
	case *scan.LFIResult:
		out = flattenLFI(target, r)
	case *scan.JWTResult:
		out = flattenJWT(target, r)
	case *scan.OpenAPIResult:
		out = flattenOpenAPI(target, r)
	case *scan.FaviconResult:
		out = flattenFavicon(target, r)
	case *scan.CMSResult:
		out = flattenCMS(target, r)
	case *scan.SecurityTrailsResult:
		out = flattenSecurityTrails(target, r)
	case *scan.CORSResult:
		out = flattenCORS(target, r)
	case *scan.RedirectResult:
		out = flattenRedirect(target, r)
	case *scan.XSSResult:
		out = flattenXSS(target, r)
	case *scan.CrawlResult:
		out = flattenCrawl(target, r)
	case *scan.PassiveResult:
		out = flattenPassive(target, r)
	case *scan.ProbeResult:
		out = flattenProbe(target, r)
	case scan.HeaderResults:
		out = flattenHeaders(target, r)
	case []scan.HeaderResult:
		// the headers module appends a literal []HeaderResult, not the named
		// slice type; both reach here so cover both.
		out = flattenHeaders(target, r)
	case scan.SecurityHeaderResults:
		out = flattenSecurityHeaders(target, r)
	case []scan.SecurityHeaderResult:
		out = flattenSecurityHeaders(target, r)
	case scan.DirectoryResults:
		out = flattenDirlist(target, r)
	case []scan.DirectoryResult:
		out = flattenDirlist(target, r)
	case scan.CloudStorageResults:
		out = flattenCloudStorage(target, r)
	case []scan.CloudStorageResult:
		out = flattenCloudStorage(target, r)
	case scan.DorkResults:
		out = flattenDork(target, r)
	case []scan.DorkResult:
		out = flattenDork(target, r)
	case scan.SubdomainTakeoverResults:
		out = flattenTakeover(target, r)
	case []scan.SubdomainTakeoverResult:
		out = flattenTakeover(target, r)
	case *frameworks.FrameworkResult:
		out = flattenFramework(target, r)
	case *js.JavascriptScanResult:
		out = flattenJS(target, r)
	case *modules.Result:
		// yaml/builtin modules carry their own module id; honor it over the
		// passed-in module so per-module findings stay attributed correctly.
		out = flattenModule(target, r)
	case []output.ResultEvent:
		out = flattenNuclei(target, r)
	case []string:
		// dnslist/portscan/git all hand back a bare []string of discovered
		// items; module disambiguates which inventory it is.
		out = flattenStrings(target, module, r)
	default:
		// unknown type: emit a loud placeholder rather than dropping it.
		out = []Finding{{
			Target:   target,
			Module:   module,
			Severity: SeverityUnknown,
			Key:      key(module, "unhandled"),
			Title:    fmt.Sprintf("unhandled result type %T", result),
			Raw:      fmt.Sprintf("%T", result),
		}}
	}
	// some flatten* funcs iterate a Go map (js env vars), which randomizes
	// order per run; sort by Key here once so all report output is stable.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func flattenShodan(target string, r *scan.ShodanResult) []Finding {
	if r == nil {
		return nil
	}
	// one host snapshot -> one inventory finding; vulns are the interesting bit
	// so they bump severity and ride along in the evidence string.
	sev := sevRecon
	if len(r.Vulns) > 0 {
		sev = SeverityHigh
	}
	raw := fmt.Sprintf("%d ports", len(r.Ports))
	if len(r.Vulns) > 0 {
		raw = fmt.Sprintf("%s, %d vulns", raw, len(r.Vulns))
	}
	return []Finding{{
		Target:   target,
		Module:   "shodan",
		Severity: sev,
		Key:      key("shodan", r.IP),
		Title:    "shodan host " + r.IP,
		Raw:      raw,
	}}
}

func flattenSQL(target string, r *scan.SQLResult) []Finding {
	if r == nil {
		return nil
	}
	out := make([]Finding, 0, len(r.AdminPanels)+len(r.DatabaseErrors)+len(r.ExposedPorts))
	for i := 0; i < len(r.AdminPanels); i++ {
		p := r.AdminPanels[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "sql",
			Severity: sevAdminPanel,
			Key:      key("sql", "admin:"+p.URL),
			Title:    p.Type + " admin panel",
			Raw:      fmt.Sprintf("%s (%d)", p.URL, p.Status),
		})
	}
	for i := 0; i < len(r.DatabaseErrors); i++ {
		e := r.DatabaseErrors[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "sql",
			Severity: sevDBError,
			Key:      key("sql", "dberr:"+e.URL+":"+e.DatabaseType),
			Title:    e.DatabaseType + " error disclosure",
			Raw:      e.ErrorPattern,
		})
	}
	for i := 0; i < len(r.ExposedPorts); i++ {
		p := r.ExposedPorts[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "sql",
			Severity: SeverityMedium,
			Key:      key("sql", fmt.Sprintf("port:%d", p)),
			Title:    fmt.Sprintf("exposed db port %d", p),
			Raw:      fmt.Sprintf("%d", p),
		})
	}
	return out
}

func flattenLFI(target string, r *scan.LFIResult) []Finding {
	if r == nil {
		return nil
	}
	out := make([]Finding, 0, len(r.Vulnerabilities))
	for i := 0; i < len(r.Vulnerabilities); i++ {
		v := r.Vulnerabilities[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "lfi",
			Severity: ParseSeverity(v.Severity),
			Key:      key("lfi", v.URL+":"+v.Parameter),
			Title:    "lfi via " + v.Parameter,
			Raw:      v.Evidence,
		})
	}
	return out
}

func flattenJWT(target string, r *scan.JWTResult) []Finding {
	if r == nil {
		return nil
	}
	out := make([]Finding, 0, len(r.Tokens))
	for i := 0; i < len(r.Tokens); i++ {
		t := r.Tokens[i]
		// one finding per weakness, not per token: a token with alg:none and a
		// weak key is two distinct issues a consumer wants to diff separately.
		for j := 0; j < len(t.Issues); j++ {
			iss := t.Issues[j]
			out = append(out, Finding{
				Target:   target,
				Module:   "jwt",
				Severity: ParseSeverity(iss.Severity),
				Key:      key("jwt", t.Source+":"+iss.Kind),
				Title:    "jwt " + iss.Kind,
				Raw:      iss.Detail,
			})
		}
	}
	return out
}

func flattenOpenAPI(target string, r *scan.OpenAPIResult) []Finding {
	if r == nil {
		return nil
	}
	return []Finding{{
		Target:   target,
		Module:   "openapi",
		Severity: ParseSeverity(r.Severity),
		Key:      key("openapi", r.SpecURL),
		Title:    "openapi spec exposed",
		Raw:      fmt.Sprintf("%s (%d endpoints)", r.SpecURL, len(r.Endpoints)),
	}}
}

func flattenFavicon(target string, r *scan.FaviconResult) []Finding {
	if r == nil {
		return nil
	}
	// a matched fingerprint is a real signal; an unmatched hash is just inventory
	// (still useful as a shodan pivot, so we keep it at recon).
	sev := sevRecon
	title := fmt.Sprintf("favicon hash %d", r.Hash)
	if r.Tech != "" {
		sev = SeverityLow
		title = r.Tech + " (favicon)"
	}
	return []Finding{{
		Target:   target,
		Module:   "favicon",
		Severity: sev,
		Key:      key("favicon", fmt.Sprintf("%d", r.Hash)),
		Title:    title,
		Raw:      r.ShodanQ,
	}}
}

func flattenCMS(target string, r *scan.CMSResult) []Finding {
	if r == nil || r.Name == "" {
		return nil
	}
	return []Finding{{
		Target:   target,
		Module:   "cms",
		Severity: sevRecon,
		Key:      key("cms", r.Name),
		Title:    r.Name + " detected",
		Raw:      strings.TrimSpace(r.Name + " " + r.Version),
	}}
}

func flattenSecurityTrails(target string, r *scan.SecurityTrailsResult) []Finding {
	if r == nil {
		return nil
	}
	out := make([]Finding, 0, len(r.Subdomains)+len(r.AssociatedDomains))
	for i := 0; i < len(r.Subdomains); i++ {
		d := r.Subdomains[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "securitytrails",
			Severity: sevRecon,
			Key:      key("securitytrails", "sub:"+d),
			Title:    "subdomain " + d,
			Raw:      d,
		})
	}
	for i := 0; i < len(r.AssociatedDomains); i++ {
		d := r.AssociatedDomains[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "securitytrails",
			Severity: sevRecon,
			Key:      key("securitytrails", "assoc:"+d),
			Title:    "associated domain " + d,
			Raw:      d,
		})
	}
	return out
}

func flattenCORS(target string, r *scan.CORSResult) []Finding {
	if r == nil {
		return nil
	}
	out := make([]Finding, 0, len(r.Findings))
	for i := 0; i < len(r.Findings); i++ {
		f := r.Findings[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "cors",
			Severity: ParseSeverity(f.Severity),
			Key:      key("cors", f.URL+":"+f.OriginTested),
			Title:    f.Note,
			Raw:      "allow-origin: " + f.AllowOrigin,
		})
	}
	return out
}

func flattenRedirect(target string, r *scan.RedirectResult) []Finding {
	if r == nil {
		return nil
	}
	out := make([]Finding, 0, len(r.Findings))
	for i := 0; i < len(r.Findings); i++ {
		f := r.Findings[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "redirect",
			Severity: ParseSeverity(f.Severity),
			Key:      key("redirect", f.URL+":"+f.Parameter+":"+f.Via),
			Title:    "open redirect via " + f.Parameter,
			Raw:      f.Location,
		})
	}
	return out
}

func flattenXSS(target string, r *scan.XSSResult) []Finding {
	if r == nil {
		return nil
	}
	out := make([]Finding, 0, len(r.Findings))
	for i := 0; i < len(r.Findings); i++ {
		f := r.Findings[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "xss",
			Severity: ParseSeverity(f.Severity),
			Key:      key("xss", f.URL+":"+f.Parameter+":"+f.Context),
			Title:    "reflected xss in " + f.Parameter,
			Raw:      strings.Join(f.SurvivedRaw, " "),
		})
	}
	return out
}

func flattenCrawl(target string, r *scan.CrawlResult) []Finding {
	if r == nil {
		return nil
	}
	out := make([]Finding, 0, len(r.URLs))
	for i := 0; i < len(r.URLs); i++ {
		u := r.URLs[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "crawl",
			Severity: sevRecon,
			Key:      key("crawl", u),
			Title:    "crawled url",
			Raw:      u,
		})
	}
	return out
}

func flattenPassive(target string, r *scan.PassiveResult) []Finding {
	if r == nil {
		return nil
	}
	out := make([]Finding, 0, len(r.Subdomains)+len(r.URLs))
	for i := 0; i < len(r.Subdomains); i++ {
		s := r.Subdomains[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "passive",
			Severity: sevRecon,
			Key:      key("passive", "sub:"+s),
			Title:    "passive subdomain " + s,
			Raw:      s,
		})
	}
	for i := 0; i < len(r.URLs); i++ {
		u := r.URLs[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "passive",
			Severity: sevRecon,
			Key:      key("passive", "url:"+u),
			Title:    "passive url",
			Raw:      u,
		})
	}
	return out
}

func flattenProbe(target string, r *scan.ProbeResult) []Finding {
	if r == nil || !r.Alive {
		// a dead probe isn't a finding, just an absent host.
		return nil
	}
	return []Finding{{
		Target:   target,
		Module:   "probe",
		Severity: sevRecon,
		Key:      key("probe", r.URL),
		Title:    fmt.Sprintf("alive %d", r.StatusCode),
		Raw:      strings.TrimSpace(fmt.Sprintf("%d %s", r.StatusCode, r.Title)),
	}}
}

func flattenHeaders(target string, rs []scan.HeaderResult) []Finding {
	out := make([]Finding, 0, len(rs))
	// a multi-valued header (Set-Cookie is the canonical case) emits one
	// HeaderResult per value, and keying on the name alone collapses every
	// value but the first onto one dedup Key. disambiguate by how many times
	// the name has been seen rather than by the value: the value would
	// destabilize every volatile single-valued header (Date, ETag, Age, CF-Ray)
	// against the run-stable Key contract.
	//
	// the count is per name, not the slice index. headers.go ranges over
	// resp.Header, so a name's position in the slice is randomized per run
	// while the order of values within one name is preserved.
	//
	// the separator is ":", which rfc7230 excludes from a header field-name, so
	// the suffix cannot collide with a real header. "#" would: it is a valid
	// tchar, so a header literally named "Foo#1" would take the key of the
	// second "Foo".
	seen := make(map[string]int, len(rs))
	for i := 0; i < len(rs); i++ {
		h := rs[i]
		identifier := h.Name
		if n := seen[h.Name]; n > 0 {
			identifier += ":" + strconv.Itoa(n)
		}
		seen[h.Name]++
		out = append(out, Finding{
			Target:   target,
			Module:   "headers",
			Severity: sevRecon,
			Key:      key("headers", identifier),
			Title:    h.Name,
			Raw:      h.Value,
		})
	}
	return out
}

func flattenSecurityHeaders(target string, rs []scan.SecurityHeaderResult) []Finding {
	out := make([]Finding, 0, len(rs))
	for i := 0; i < len(rs); i++ {
		h := rs[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "security_headers",
			Severity: ParseSeverity(h.Severity),
			Key:      key("security_headers", h.Header),
			Title:    h.Header,
			Raw:      h.Note,
		})
	}
	return out
}

// dirInteresting bounds the "noteworthy" 3xx range for a listed directory; a
// redirect (>=300) or anything past it is worth more than a plain 200 hit.
const dirRedirectFloor = 300

func flattenDirlist(target string, rs []scan.DirectoryResult) []Finding {
	out := make([]Finding, 0, len(rs))
	for i := 0; i < len(rs); i++ {
		d := rs[i]
		sev := sevRecon
		if d.StatusCode >= dirRedirectFloor {
			sev = SeverityLow
		}
		out = append(out, Finding{
			Target:   target,
			Module:   "dirlist",
			Severity: sev,
			Key:      key("dirlist", d.Url),
			Title:    fmt.Sprintf("%s [%d]", d.Url, d.StatusCode),
			Raw:      fmt.Sprintf("status=%d size=%d", d.StatusCode, d.Size),
		})
	}
	return out
}

func flattenCloudStorage(target string, rs []scan.CloudStorageResult) []Finding {
	out := make([]Finding, 0, len(rs))
	for i := 0; i < len(rs); i++ {
		b := rs[i]
		sev := sevRecon
		if b.IsPublic {
			sev = sevPublicS3
		}
		title := "bucket " + b.BucketName
		if b.IsPublic {
			title = "public bucket " + b.BucketName
		}
		out = append(out, Finding{
			Target:   target,
			Module:   "cloudstorage",
			Severity: sev,
			Key:      key("cloudstorage", b.BucketName),
			Title:    title,
			Raw:      fmt.Sprintf("public=%t", b.IsPublic),
		})
	}
	return out
}

func flattenDork(target string, rs []scan.DorkResult) []Finding {
	out := make([]Finding, 0, len(rs))
	for i := 0; i < len(rs); i++ {
		d := rs[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "dork",
			Severity: sevRecon,
			Key:      key("dork", d.Url),
			Title:    fmt.Sprintf("dork hit [%s]", d.Dork),
			Raw:      d.Url,
		})
	}
	return out
}

func flattenTakeover(target string, rs []scan.SubdomainTakeoverResult) []Finding {
	out := make([]Finding, 0, len(rs))
	for i := 0; i < len(rs); i++ {
		t := rs[i]
		// only the vulnerable ones are findings; a safe cname is noise here.
		if !t.Vulnerable {
			continue
		}
		// a "potential" result only matched a body fingerprint and could not be
		// checked against the cname (lookup unavailable), so it does not earn
		// the same severity as a cname-confirmed takeover.
		sev := sevTakeover
		if t.Confidence == "potential" {
			sev = SeverityMedium
		}
		out = append(out, Finding{
			Target:   target,
			Module:   "subdomain_takeover",
			Severity: sev,
			Key:      key("subdomain_takeover", t.Subdomain),
			Title:    "takeover: " + t.Subdomain,
			Raw:      t.Service,
		})
	}
	return out
}

func flattenFramework(target string, r *frameworks.FrameworkResult) []Finding {
	if r == nil || r.Name == "" {
		return nil
	}
	// framework risk maps onto severity; an unset risk falls back to recon.
	sev := ParseSeverity(r.RiskLevel)
	if sev == SeverityUnknown {
		sev = sevRecon
	}
	raw := strings.TrimSpace(r.Name + " " + r.Version)
	if len(r.CVEs) > 0 {
		raw = fmt.Sprintf("%s, %d cves", raw, len(r.CVEs))
	}
	return []Finding{{
		Target:     target,
		Module:     "framework",
		Severity:   sev,
		Key:        key("framework", r.Name),
		Title:      r.Name + " detected",
		Raw:        raw,
		Confidence: r.Confidence,
	}}
}

func flattenJS(target string, r *js.JavascriptScanResult) []Finding {
	if r == nil {
		return nil
	}
	supabase := r.SupabaseFindings()
	out := make([]Finding, 0, len(r.SecretMatches)+len(supabase)+len(r.Endpoints)+len(r.FoundEnvironmentVars))
	for i := 0; i < len(r.SecretMatches); i++ {
		s := r.SecretMatches[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "js",
			Severity: sevSecret,
			Key:      key("js", "secret:"+s.Rule+":"+s.Source),
			Title:    "secret: " + s.Rule,
			Raw:      s.Source,
		})
	}
	for i := 0; i < len(supabase); i++ {
		s := supabase[i]
		// a non-anon role on an exposed key is the real bug; anon is just recon.
		sev := sevRecon
		if s.Role != "" && s.Role != "anon" {
			sev = SeverityHigh
		}
		out = append(out, Finding{
			Target:   target,
			Module:   "js",
			Severity: sev,
			Key:      key("js", "supabase:"+s.ProjectId),
			Title:    "supabase project " + s.ProjectId,
			Raw:      fmt.Sprintf("role=%s collections=%d", s.Role, s.Collections),
		})
	}
	for i := 0; i < len(r.Endpoints); i++ {
		e := r.Endpoints[i]
		out = append(out, Finding{
			Target:   target,
			Module:   "js",
			Severity: sevRecon,
			Key:      key("js", "endpoint:"+e),
			Title:    "js endpoint",
			Raw:      e,
		})
	}
	// map order is random here; Flatten sorts by Key (see comment above sort.SliceStable).
	for name, value := range r.FoundEnvironmentVars {
		out = append(out, Finding{
			Target:   target,
			Module:   "js",
			Severity: sevSecret,
			Key:      key("js", "env:"+name),
			Title:    "env var " + name,
			Raw:      value,
		})
	}
	return out
}

func flattenModule(target string, r *modules.Result) []Finding {
	if r == nil {
		return nil
	}
	module := r.ResultType()
	out := make([]Finding, 0, len(r.Findings))
	for i := 0; i < len(r.Findings); i++ {
		f := r.Findings[i]
		out = append(out, Finding{
			Target:   target,
			Module:   module,
			Severity: ParseSeverity(f.Severity),
			Key:      key(module, f.URL),
			Title:    module + " finding",
			Raw:      f.Evidence,
		})
	}
	return out
}

func flattenNuclei(target string, events []output.ResultEvent) []Finding {
	out := make([]Finding, 0, len(events))
	for i := 0; i < len(events); i++ {
		e := events[i]
		// host is the most reliable per-hit identifier; matched-at sharpens it
		// when several templates fire on one host.
		ident := e.TemplateID + ":" + e.Host
		if e.Matched != "" {
			ident = e.TemplateID + ":" + e.Matched
		}
		out = append(out, Finding{
			Target:   target,
			Module:   "nuclei",
			Severity: ParseSeverity(e.Info.SeverityHolder.Severity.String()),
			Key:      key("nuclei", ident),
			Title:    e.Info.Name,
			Raw:      e.Matched,
		})
	}
	return out
}

func flattenStrings(target, module string, items []string) []Finding {
	out := make([]Finding, 0, len(items))
	for i := 0; i < len(items); i++ {
		v := items[i]
		out = append(out, Finding{
			Target:   target,
			Module:   module,
			Severity: sevRecon,
			Key:      key(module, v),
			Title:    module + " item",
			Raw:      v,
		})
	}
	return out
}
