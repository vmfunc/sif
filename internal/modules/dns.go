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
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
	retryabledns "github.com/projectdiscovery/retryabledns"
)

// dnsMaxRetries is how many times the resolver rotates through the pool on a
// timeout before giving up.
const dnsMaxRetries = 3

// defaultDNSResolvers is the bundled pool: fast public anycast servers.
var defaultDNSResolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

// dnsRequestType maps a module's record-type string to its dns type code. An
// empty type defaults to A; ANY is deliberately not the default (RFC 8482
// discourages relying on ANY against the public resolvers).
var dnsRequestType = map[string]uint16{
	"":      dns.TypeA,
	"a":     dns.TypeA,
	"aaaa":  dns.TypeAAAA,
	"cname": dns.TypeCNAME,
	"mx":    dns.TypeMX,
	"ns":    dns.TypeNS,
	"txt":   dns.TypeTXT,
	"soa":   dns.TypeSOA,
	"srv":   dns.TypeSRV,
	"caa":   dns.TypeCAA,
	"ptr":   dns.TypePTR,
	"any":   dns.TypeANY,
}

// dnsResolver is the slice of the retryabledns client the executor needs; tests
// inject a fake through newDNSResolver. Close releases the client's pooled
// connections; ExecuteDNSModule builds a fresh client per call, so leaving this
// out leaks a connection per query.
type dnsResolver interface {
	Query(host string, requestType uint16) (*retryabledns.DNSData, error)
	Close()
}

// newDNSResolver builds a resolver over the bundled pool with the given timeout.
// It is a package var so tests can supply a fake without touching the network.
var newDNSResolver = func(timeout time.Duration) (dnsResolver, error) {
	opts := retryabledns.Options{
		BaseResolvers: defaultDNSResolvers,
		MaxRetries:    dnsMaxRetries,
	}
	if timeout > 0 {
		opts.Timeout = timeout
	}
	client, err := retryabledns.NewWithOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("build dns resolver: %w", err)
	}
	client.TCPFallback = true
	return client, nil
}

// dnsResponse holds the parts of a resolved answer a matcher can target.
type dnsResponse struct {
	answer []string // the resource records, one per line
	rcode  string   // the response status, e.g. NOERROR or NXDOMAIN
	raw    string   // the full text of the response message
}

// validateDNS rejects, at load time, a dns config the executor cannot run: an
// unknown record type, or a matcher type other than word or regex (status is
// http only).
func validateDNS(cfg *DNSConfig) error {
	if _, ok := dnsRequestType[strings.ToLower(cfg.Type)]; !ok {
		return fmt.Errorf("unsupported dns record type %q", cfg.Type)
	}
	for i := range cfg.Matchers {
		switch cfg.Matchers[i].Type {
		case "word", "regex":
		default:
			return fmt.Errorf("dns matcher type %q is not supported (use word or regex)", cfg.Matchers[i].Type)
		}
	}
	return nil
}

// ExecuteDNSModule resolves the configured name and record type, then applies
// the module's matchers and extractors to the answer.
func ExecuteDNSModule(ctx context.Context, target string, def *YAMLModule, opts Options) (*Result, error) {
	if def.DNS == nil {
		return nil, fmt.Errorf("no DNS configuration")
	}
	cfg := def.DNS
	result := &Result{
		ModuleID: def.ID,
		Target:   target,
		Findings: make([]Finding, 0),
	}

	qtype, ok := dnsRequestType[strings.ToLower(cfg.Type)]
	if !ok {
		return nil, fmt.Errorf("unsupported dns record type %q", cfg.Type)
	}

	resolver, err := newDNSResolver(opts.Timeout)
	if err != nil {
		return nil, err
	}
	defer resolver.Close()

	// retryabledns has no context hook, so honor cancellation before the lookup.
	if err := ctx.Err(); err != nil {
		return result, err
	}

	name := dnsName(cfg.Name, target)
	data, err := resolver.Query(name, qtype)
	if err != nil {
		return nil, fmt.Errorf("dns query %q: %w", name, err)
	}

	resp := newDNSResponse(data)
	if !checkDNSMatchers(cfg.Matchers, resp) {
		return result, nil
	}

	result.Findings = append(result.Findings, Finding{
		Severity:  def.Info.Severity,
		Evidence:  truncateEvidence(resp.raw),
		Extracted: runDNSExtractors(cfg.Extractors, resp),
	})
	return result, nil
}

// newDNSResponse extracts the matchable parts from a resolved answer. The raw
// text comes from RawResp (the single final message) rather than data.Raw, which
// the resolver's retry loop concatenates across attempts.
func newDNSResponse(data *retryabledns.DNSData) dnsResponse {
	if data == nil {
		return dnsResponse{}
	}
	raw := data.Raw
	if data.RawResp != nil {
		raw = data.RawResp.String()
	}
	return dnsResponse{
		answer: data.AllRecords,
		rcode:  data.StatusCode,
		raw:    raw,
	}
}

// getDNSPart returns the slice of the response a matcher or extractor targets.
// The default (and the explicit "all"/"body") is the full response text;
// "answer" is the record set; "rcode" is the response status.
func getDNSPart(part string, resp dnsResponse) string {
	switch strings.ToLower(part) {
	case "answer":
		return strings.Join(resp.answer, "\n")
	case "rcode":
		return resp.rcode
	default:
		return resp.raw
	}
}

// checkDNSMatchers evaluates all matchers against the response with AND logic.
func checkDNSMatchers(matchers []Matcher, resp dnsResponse) bool {
	if len(matchers) == 0 {
		return false
	}

	for i := range matchers {
		matched := checkDNSMatcher(&matchers[i], resp)
		if matchers[i].Negative {
			matched = !matched
		}
		if !matched {
			return false // AND logic
		}
	}

	return true
}

// checkDNSMatcher evaluates a single matcher. The status matcher type is HTTP
// only; match a response code with a word or regex matcher on part "rcode".
func checkDNSMatcher(m *Matcher, resp dnsResponse) bool {
	part := getDNSPart(m.Part, resp)

	switch m.Type {
	case "word":
		return checkWords(part, m.Words, m.Condition, m.CaseInsensitive)
	case "regex":
		return checkRegex(part, m.Regex, m.Condition)
	default:
		return false
	}
}

// runDNSExtractors pulls regex captures from the response. DNS answers are text,
// so regex is the available extractor; other types are skipped.
func runDNSExtractors(extractors []Extractor, resp dnsResponse) map[string]string {
	if len(extractors) == 0 {
		return nil
	}

	result := make(map[string]string)
	for _, e := range extractors {
		if e.Type != "regex" {
			continue
		}
		part := getDNSPart(e.Part, resp)
		for _, pattern := range e.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			matches := re.FindStringSubmatch(part)
			if len(matches) > e.Group {
				result[e.Name] = matches[e.Group]
				break
			}
		}
	}

	return result
}

// dnsName resolves the lookup name: the module's name with {{FQDN}} replaced by
// the target host, or the bare target host when no name is set.
func dnsName(name, target string) string {
	host := dnsHost(target)
	if name == "" {
		return host
	}
	name = strings.ReplaceAll(name, "{{FQDN}}", host)
	name = strings.ReplaceAll(name, "{{fqdn}}", host)
	return name
}

// dnsHost reduces target to its hostname, stripping any scheme, port, path, or
// userinfo. A bare host is returned unchanged.
func dnsHost(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return target
	}
	// url.Parse only populates Host when a scheme is present; add one for a bare
	// host or host:port so the same parse handles every form.
	parse := target
	if !strings.Contains(parse, "://") {
		parse = "//" + parse
	}
	if u, err := url.Parse(parse); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return target
}
