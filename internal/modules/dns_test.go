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
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
	retryabledns "github.com/projectdiscovery/retryabledns"
)

// fakeDNSResolver answers from a fixture and records what it was asked.
type fakeDNSResolver struct {
	data    *retryabledns.DNSData
	err     error
	gotName string
	gotType uint16
}

func (f *fakeDNSResolver) Query(host string, requestType uint16) (*retryabledns.DNSData, error) {
	f.gotName = host
	f.gotType = requestType
	return f.data, f.err
}

func (f *fakeDNSResolver) Close() {}

// withFakeDNS installs a fake resolver for the test and restores the real one
// after; it returns the fake so a test can read back the query it received.
func withFakeDNS(t *testing.T, data *retryabledns.DNSData, queryErr error) *fakeDNSResolver {
	t.Helper()
	f := &fakeDNSResolver{data: data, err: queryErr}
	orig := newDNSResolver
	newDNSResolver = func([]string, time.Duration) (dnsResolver, error) { return f, nil }
	t.Cleanup(func() { newDNSResolver = orig })
	return f
}

func wordMatcher(part string, words ...string) Matcher {
	return Matcher{Type: "word", Part: part, Words: words}
}

// TestExecuteDNSModulePassesResolvers proves the executor hands the caller's
// resolver pool (from -resolvers via Options) to the resolver builder, rather
// than silently using the bundled public pool.
func TestExecuteDNSModulePassesResolvers(t *testing.T) {
	var gotResolvers []string
	orig := newDNSResolver
	newDNSResolver = func(resolvers []string, _ time.Duration) (dnsResolver, error) {
		gotResolvers = resolvers
		return &fakeDNSResolver{data: &retryabledns.DNSData{StatusCode: "NOERROR"}}, nil
	}
	t.Cleanup(func() { newDNSResolver = orig })

	def := dnsDef(&DNSConfig{Type: "a", Matchers: []Matcher{wordMatcher("rcode", "NOERROR")}})
	want := []string{"127.0.0.1:5353", "10.0.0.53:53"}
	if _, err := ExecuteDNSModule(context.Background(), "example.com", def, Options{Resolvers: want}); err != nil {
		t.Fatalf("ExecuteDNSModule: %v", err)
	}
	if !reflect.DeepEqual(gotResolvers, want) {
		t.Errorf("resolver pool = %v, want %v", gotResolvers, want)
	}
}

func dnsDef(cfg *DNSConfig) *YAMLModule {
	return &YAMLModule{ID: "dns-test", Type: TypeDNS, Info: YAMLModuleInfo{Severity: "info"}, DNS: cfg}
}

func TestExecuteDNSModuleMatchAndExtract(t *testing.T) {
	withFakeDNS(t, &retryabledns.DNSData{
		AllRecords: []string{"example.com. 300 IN A 93.184.216.34"},
		StatusCode: "NOERROR",
		Raw:        "example.com. 300 IN A 93.184.216.34",
	}, nil)

	def := dnsDef(&DNSConfig{
		Type:     "a",
		Matchers: []Matcher{wordMatcher("answer", "93.184.216.34")},
		Extractors: []Extractor{
			{Type: "regex", Name: "ip", Part: "answer", Regex: []string{`A (\d+\.\d+\.\d+\.\d+)`}, Group: 1},
		},
	})

	res, err := ExecuteDNSModule(context.Background(), "example.com", def, Options{})
	if err != nil {
		t.Fatalf("ExecuteDNSModule: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	if got := res.Findings[0].Extracted["ip"]; got != "93.184.216.34" {
		t.Errorf("extracted ip = %q, want 93.184.216.34", got)
	}
	if res.Findings[0].Evidence == "" {
		t.Error("evidence is empty")
	}
}

func TestExecuteDNSModuleNoMatch(t *testing.T) {
	withFakeDNS(t, &retryabledns.DNSData{AllRecords: []string{"a"}, Raw: "a", StatusCode: "NOERROR"}, nil)
	def := dnsDef(&DNSConfig{Type: "a", Matchers: []Matcher{wordMatcher("answer", "absent")}})

	res, err := ExecuteDNSModule(context.Background(), "example.com", def, Options{})
	if err != nil {
		t.Fatalf("ExecuteDNSModule: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(res.Findings))
	}
}

// TestExecuteDNSModuleParts pins the part pivot: a matcher must see only the
// slice of the response it asked for, not the whole thing.
func TestExecuteDNSModuleParts(t *testing.T) {
	data := &retryabledns.DNSData{
		AllRecords: []string{"answer-only-token"},
		StatusCode: "SERVFAIL",
		Raw:        "raw-only-token answer-only-token",
	}

	tests := []struct {
		name  string
		part  string
		word  string
		match bool
	}{
		{"default sees raw", "", "raw-only-token", true},
		{"all sees raw", "all", "raw-only-token", true},
		{"answer sees records", "answer", "answer-only-token", true},
		{"answer excludes raw-only", "answer", "raw-only-token", false},
		{"rcode sees status", "rcode", "SERVFAIL", true},
		{"rcode excludes raw-only", "rcode", "raw-only-token", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withFakeDNS(t, data, nil)
			def := dnsDef(&DNSConfig{Type: "a", Matchers: []Matcher{wordMatcher(tt.part, tt.word)}})
			res, err := ExecuteDNSModule(context.Background(), "example.com", def, Options{})
			if err != nil {
				t.Fatalf("ExecuteDNSModule: %v", err)
			}
			if got := len(res.Findings) == 1; got != tt.match {
				t.Errorf("part %q word %q matched=%v, want %v", tt.part, tt.word, got, tt.match)
			}
		})
	}
}

func TestExecuteDNSModuleTypeDispatch(t *testing.T) {
	match := []Matcher{wordMatcher("rcode", "NOERROR")}
	tests := []struct {
		typ  string
		want uint16
	}{
		{"", dns.TypeA},
		{"a", dns.TypeA},
		{"AAAA", dns.TypeAAAA},
		{"mx", dns.TypeMX},
		{"txt", dns.TypeTXT},
		{"any", dns.TypeANY},
	}
	for _, tt := range tests {
		t.Run("type "+tt.typ, func(t *testing.T) {
			f := withFakeDNS(t, &retryabledns.DNSData{StatusCode: "NOERROR", Raw: "NOERROR"}, nil)
			def := dnsDef(&DNSConfig{Type: tt.typ, Matchers: match})
			if _, err := ExecuteDNSModule(context.Background(), "example.com", def, Options{}); err != nil {
				t.Fatalf("ExecuteDNSModule: %v", err)
			}
			if f.gotType != tt.want {
				t.Errorf("type %q dispatched code %d, want %d", tt.typ, f.gotType, tt.want)
			}
		})
	}
}

func TestExecuteDNSModuleUnsupportedType(t *testing.T) {
	withFakeDNS(t, &retryabledns.DNSData{}, nil)
	def := dnsDef(&DNSConfig{Type: "zzz", Matchers: []Matcher{wordMatcher("", "x")}})
	if _, err := ExecuteDNSModule(context.Background(), "example.com", def, Options{}); err == nil {
		t.Fatal("expected error for unsupported record type")
	}
}

func TestExecuteDNSModuleName(t *testing.T) {
	tests := []struct {
		name     string
		cfgName  string
		target   string
		wantName string
	}{
		{"fqdn substitution", "_dmarc.{{FQDN}}", "example.com", "_dmarc.example.com"},
		{"empty name uses target", "", "example.com", "example.com"},
		{"url target reduced to host", "", "https://example.com:8443/p?q=1", "example.com"},
		{"explicit name kept", "fixed.example.net", "other.com", "fixed.example.net"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := withFakeDNS(t, &retryabledns.DNSData{StatusCode: "NOERROR", Raw: "NOERROR"}, nil)
			def := dnsDef(&DNSConfig{Type: "a", Name: tt.cfgName, Matchers: []Matcher{wordMatcher("rcode", "NOERROR")}})
			if _, err := ExecuteDNSModule(context.Background(), tt.target, def, Options{}); err != nil {
				t.Fatalf("ExecuteDNSModule: %v", err)
			}
			if f.gotName != tt.wantName {
				t.Errorf("resolved name = %q, want %q", f.gotName, tt.wantName)
			}
		})
	}
}

func TestCheckDNSMatchers(t *testing.T) {
	resp := dnsResponse{answer: []string{"v=spf1 include:_spf.example.com"}, rcode: "NXDOMAIN", raw: "v=spf1 include:_spf.example.com"}

	tests := []struct {
		name     string
		matchers []Matcher
		want     bool
	}{
		{"no matchers is false", nil, false},
		{"single word hit", []Matcher{wordMatcher("answer", "v=spf1")}, true},
		{"single word miss", []Matcher{wordMatcher("answer", "v=dkim")}, false},
		{"and across matchers all hit", []Matcher{wordMatcher("answer", "v=spf1"), wordMatcher("rcode", "NXDOMAIN")}, true},
		{"and across matchers one miss", []Matcher{wordMatcher("answer", "v=spf1"), wordMatcher("rcode", "NOERROR")}, false},
		{"negative inverts a miss to a hit", []Matcher{{Type: "word", Part: "answer", Words: []string{"v=dkim"}, Negative: true}}, true},
		{"negative inverts a hit to a miss", []Matcher{{Type: "word", Part: "answer", Words: []string{"v=spf1"}, Negative: true}}, false},
		{"status type never matches in dns", []Matcher{{Type: "status", Status: []int{0}}}, false},
		{"regex hit", []Matcher{{Type: "regex", Part: "answer", Regex: []string{`spf\d`}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkDNSMatchers(tt.matchers, resp); got != tt.want {
				t.Errorf("checkDNSMatchers = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunDNSExtractors(t *testing.T) {
	resp := dnsResponse{answer: []string{"example.com. 300 IN A 93.184.216.34"}, raw: "raw", rcode: "NOERROR"}

	t.Run("regex group 1", func(t *testing.T) {
		ex := []Extractor{{Type: "regex", Name: "ip", Part: "answer", Regex: []string{`A (\d+\.\d+\.\d+\.\d+)`}, Group: 1}}
		if got := runDNSExtractors(ex, resp)["ip"]; got != "93.184.216.34" {
			t.Errorf("group 1 = %q, want 93.184.216.34", got)
		}
	})
	t.Run("group 0 full match", func(t *testing.T) {
		ex := []Extractor{{Type: "regex", Name: "rec", Part: "answer", Regex: []string{`IN A [\d.]+`}, Group: 0}}
		if got := runDNSExtractors(ex, resp)["rec"]; got != "IN A 93.184.216.34" {
			t.Errorf("group 0 = %q", got)
		}
	})
	t.Run("miss sets nothing", func(t *testing.T) {
		ex := []Extractor{{Type: "regex", Name: "x", Part: "answer", Regex: []string{`nope(\d+)`}, Group: 1}}
		if _, ok := runDNSExtractors(ex, resp)["x"]; ok {
			t.Error("a non-matching extractor set a value")
		}
	})
	t.Run("non-regex type skipped", func(t *testing.T) {
		ex := []Extractor{{Type: "kv", Name: "k", Part: "answer"}}
		if _, ok := runDNSExtractors(ex, resp)["k"]; ok {
			t.Error("a non-regex extractor produced a value")
		}
	})
	t.Run("uncompilable pattern skipped", func(t *testing.T) {
		// the bad pattern is skipped, the next one still matches.
		ex := []Extractor{{Type: "regex", Name: "x", Part: "answer", Regex: []string{"[", `(A)`}, Group: 1}}
		if got := runDNSExtractors(ex, resp)["x"]; got != "A" {
			t.Errorf("after skipping an invalid regex, got %q, want A", got)
		}
	})
	t.Run("no extractors is nil", func(t *testing.T) {
		if runDNSExtractors(nil, resp) != nil {
			t.Error("want nil for no extractors")
		}
	})
}

func TestExecuteDNSModuleContextCancel(t *testing.T) {
	withFakeDNS(t, &retryabledns.DNSData{StatusCode: "NOERROR", Raw: "NOERROR"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	def := dnsDef(&DNSConfig{Type: "a", Matchers: []Matcher{wordMatcher("rcode", "NOERROR")}})
	res, err := ExecuteDNSModule(ctx, "example.com", def, Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("got %d findings on cancel, want 0", len(res.Findings))
	}
}

func TestExecuteDNSModuleResolverError(t *testing.T) {
	withFakeDNS(t, nil, fmt.Errorf("server failure"))
	def := dnsDef(&DNSConfig{Type: "a", Matchers: []Matcher{wordMatcher("rcode", "x")}})
	if _, err := ExecuteDNSModule(context.Background(), "example.com", def, Options{}); err == nil {
		t.Fatal("expected error when the query fails")
	}
}

func TestExecuteDNSModuleResolverBuildError(t *testing.T) {
	orig := newDNSResolver
	newDNSResolver = func([]string, time.Duration) (dnsResolver, error) { return nil, fmt.Errorf("build failed") }
	t.Cleanup(func() { newDNSResolver = orig })

	def := dnsDef(&DNSConfig{Type: "a", Matchers: []Matcher{wordMatcher("rcode", "x")}})
	if _, err := ExecuteDNSModule(context.Background(), "example.com", def, Options{}); err == nil {
		t.Fatal("expected error when the resolver cannot be built")
	}
}

func TestExecuteDNSModuleNoConfig(t *testing.T) {
	def := &YAMLModule{ID: "x", Type: TypeDNS}
	if _, err := ExecuteDNSModule(context.Background(), "example.com", def, Options{}); err == nil {
		t.Fatal("expected error when DNS config is nil")
	}
}

func TestNewDNSResponseRawResp(t *testing.T) {
	// RawResp wins over Raw, which the resolver concatenates across retries.
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	got := newDNSResponse(&retryabledns.DNSData{Raw: "concatenated", RawResp: msg})
	if got.raw == "concatenated" || got.raw == "" {
		t.Errorf("raw = %q, want the RawResp text", got.raw)
	}
	if newDNSResponse(nil).raw != "" {
		t.Error("nil data should yield an empty response")
	}
}

func TestDNSHost(t *testing.T) {
	cases := map[string]string{
		"example.com":                       "example.com",
		"https://example.com:8443/path?q=1": "example.com",
		"http://user:pass@host.tld":         "host.tld",
		"1.2.3.4:53":                        "1.2.3.4",
		"[2606:4700::1111]:53":              "2606:4700::1111",
		"/justpath":                         "/justpath",
		"":                                  "",
	}
	for in, want := range cases {
		if got := dnsHost(in); got != want {
			t.Errorf("dnsHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateDNS(t *testing.T) {
	tests := []struct {
		name string
		cfg  *DNSConfig
		ok   bool
	}{
		{"empty type defaults to a", &DNSConfig{}, true},
		{"known type and matchers", &DNSConfig{Type: "TXT", Matchers: []Matcher{{Type: "word"}, {Type: "regex"}}}, true},
		{"no matchers is allowed", &DNSConfig{Type: "a"}, true},
		{"unknown record type", &DNSConfig{Type: "zzz"}, false},
		{"status matcher rejected", &DNSConfig{Type: "a", Matchers: []Matcher{{Type: "status"}}}, false},
		{"unknown matcher type rejected", &DNSConfig{Type: "a", Matchers: []Matcher{{Type: "word"}, {Type: "size"}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDNS(tt.cfg)
			if (err == nil) != tt.ok {
				t.Errorf("validateDNS = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestParseDNSValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	good := write("good.yaml", "id: ok\ntype: dns\ndns:\n  type: txt\n  matchers:\n    - type: word\n      words: [x]\n")
	if _, err := ParseYAMLModule(good); err != nil {
		t.Fatalf("valid dns module rejected: %v", err)
	}

	badType := write("badtype.yaml", "id: bt\ntype: dns\ndns:\n  type: zzz\n")
	if _, err := ParseYAMLModule(badType); err == nil {
		t.Fatal("unknown record type accepted")
	}

	badMatcher := write("badmatcher.yaml", "id: bm\ntype: dns\ndns:\n  type: a\n  matchers:\n    - type: status\n      status: [0]\n")
	if _, err := ParseYAMLModule(badMatcher); err == nil {
		t.Fatal("status matcher on dns accepted")
	}
}

func TestNewDNSResolverBuildsClient(t *testing.T) {
	r, err := newDNSResolver(nil, 2*time.Second)
	if err != nil {
		t.Fatalf("newDNSResolver: %v", err)
	}
	if r == nil {
		t.Fatal("newDNSResolver returned a nil resolver")
	}
	r.Close()
}

// TestNewDNSResolverFloorsZeroTimeout pins the timeout floor: opts.Timeout <= 0
// must not reach retryabledns as a literal zero, since retryabledns applies no
// default of its own and a zero-timeout dns.Client blocks forever on a
// non-responsive resolver. A black-hole UDP listener (accepts the query,
// never replies) stands in for that non-responsive resolver.
func TestNewDNSResolverFloorsZeroTimeout(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			// never reply: this is the black hole.
		}
	}()

	origResolvers := defaultDNSResolvers
	defaultDNSResolvers = []string{pc.LocalAddr().String()}
	t.Cleanup(func() { defaultDNSResolvers = origResolvers })

	r, err := newDNSResolver(nil, 0)
	if err != nil {
		t.Fatalf("newDNSResolver: %v", err)
	}

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := r.Query("example.com", dns.TypeA)
		done <- err
	}()

	// the executor retries dnsMaxRetries times, each capped at the floored
	// timeout, so the bound is a multiple of it, not the timeout itself.
	bound := time.Duration(dnsMaxRetries) * defaultDNSTimeout
	select {
	case err := <-done:
		elapsed := time.Since(start)
		t.Logf("query against a black-hole resolver returned after %v: %v", elapsed, err)
		if elapsed > bound+2*time.Second {
			t.Errorf("query took %v, want it bounded by ~%v (floored timeout x retries)", elapsed, bound)
		}
	case <-time.After(bound + 5*time.Second):
		t.Fatal("query against a black-hole resolver did not return in bounded time; a zero timeout is hanging forever")
	}
}
