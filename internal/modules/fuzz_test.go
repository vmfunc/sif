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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/vmfunc/sif/internal/httpx"
)

// legacyPayloads builds the single anonymous set the sequence form desugars to,
// so existing tests that used a flat []string keep their exact meaning.
func legacyPayloads(vals []string) PayloadSets {
	if len(vals) == 0 {
		return PayloadSets{}
	}
	return PayloadSets{Sets: []PayloadSet{{Name: "payload", Values: vals}}}
}

func TestPayloadSetsUnmarshalSequence(t *testing.T) {
	var cfg HTTPConfig
	if err := yaml.Unmarshal([]byte("payloads: [\"a\", \"b\"]\n"), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []PayloadSet{{Name: "payload", Values: []string{"a", "b"}}}
	if !reflect.DeepEqual(cfg.Payloads.Sets, want) {
		t.Errorf("sequence form = %+v, want %+v", cfg.Payloads.Sets, want)
	}
}

func TestPayloadSetsUnmarshalMappingOrdered(t *testing.T) {
	// both keys are inline here (not file-backed): a file-backed entry is
	// rejected by validate() in this task (see TestPayloadSetsValidation), so
	// mixing one in would make this parse fail rather than exercise ordering.
	var cfg HTTPConfig
	src := "payloads:\n  user: [\"admin\", \"root\"]\n  role: [\"admin\", \"user\"]\n"
	if err := yaml.Unmarshal([]byte(src), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []PayloadSet{
		{Name: "user", Values: []string{"admin", "root"}},
		{Name: "role", Values: []string{"admin", "user"}},
	}
	if !reflect.DeepEqual(cfg.Payloads.Sets, want) {
		t.Errorf("mapping form = %+v, want %+v", cfg.Payloads.Sets, want)
	}
}

func TestPayloadSetsValidation(t *testing.T) {
	// duplicate set name
	if err := yaml.Unmarshal([]byte("payloads:\n  x: [\"1\"]\n  x: [\"2\"]\n"), &HTTPConfig{}); err == nil {
		t.Error("duplicate set name accepted")
	}
	// reserved builtin name
	if err := yaml.Unmarshal([]byte("payloads:\n  BaseURL: [\"1\"]\n"), &HTTPConfig{}); err == nil {
		t.Error("BaseURL set name accepted")
	}
	// file-backed set now parses (loaded at resolve time)
	if err := yaml.Unmarshal([]byte("payloads:\n  p: creds.txt\n"), &HTTPConfig{}); err != nil {
		t.Errorf("file-backed set rejected: %v", err)
	}
}

func TestResolveSetsLoadsFile(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "creds.txt")
	if err := os.WriteFile(wl, []byte("admin\nroot\n\nguest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &HTTPConfig{
		Paths: []string{"{{BaseURL}}/?u={{user}}"},
		Payloads: PayloadSets{Sets: []PayloadSet{
			{Name: "user", File: wl},
		}},
	}
	got, err := generateHTTPRequests("http://t", cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// loadWordlist skips the blank line, leaving 3 words.
	want := []string{"http://t/?u=admin", "http://t/?u=guest", "http://t/?u=root"}
	urls := reqURLs(got)
	if !reflect.DeepEqual(urls, want) {
		t.Errorf("file-set urls = %v, want %v", urls, want)
	}
}

func TestResolveSetsMissingFile(t *testing.T) {
	cfg := &HTTPConfig{
		Paths:    []string{"{{BaseURL}}/?u={{user}}"},
		Payloads: PayloadSets{Sets: []PayloadSet{{Name: "user", File: "/no/such/wordlist"}}},
	}
	if _, err := generateHTTPRequests("http://t", cfg); err == nil {
		t.Error("missing wordlist accepted")
	}
}

func TestStreamRequestsMultiSetClusterbomb(t *testing.T) {
	cfg := &HTTPConfig{
		Paths: []string{"{{BaseURL}}/x?u={{user}}&p={{pass}}"},
		Payloads: PayloadSets{Sets: []PayloadSet{
			{Name: "user", Values: []string{"a", "b"}},
			{Name: "pass", Values: []string{"1", "2"}},
		}},
	}
	got, err := generateHTTPRequests("http://t", cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// paths outer, sets in declaration order, rightmost (pass) fastest.
	want := []string{
		"http://t/x?u=a&p=1", "http://t/x?u=a&p=2",
		"http://t/x?u=b&p=1", "http://t/x?u=b&p=2",
	}
	urls := reqURLs(got) // reqURLs sorts; sort want too
	sort.Strings(want)
	if !reflect.DeepEqual(urls, want) {
		t.Errorf("clusterbomb urls = %v, want %v", urls, want)
	}
}

func TestStreamRequestsMultiSetPitchfork(t *testing.T) {
	cfg := &HTTPConfig{
		Attack: "pitchfork",
		Paths:  []string{"{{BaseURL}}/a?u={{user}}&p={{pass}}", "{{BaseURL}}/b?u={{user}}&p={{pass}}"},
		Payloads: PayloadSets{Sets: []PayloadSet{
			{Name: "user", Values: []string{"a", "b", "c"}},
			{Name: "pass", Values: []string{"1", "2"}},
		}},
	}
	got, err := generateHTTPRequests("http://t", cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// zip paths(2) x user(3) x pass(2) -> stop at 2
	want := []string{"http://t/a?u=a&p=1", "http://t/b?u=b&p=2"}
	urls := reqURLs(got)
	sort.Strings(want)
	if !reflect.DeepEqual(urls, want) {
		t.Errorf("pitchfork urls = %v, want %v", urls, want)
	}
}

func TestStreamRequestsBatteringram(t *testing.T) {
	cfg := &HTTPConfig{
		Attack: "batteringram",
		Paths:  []string{"{{BaseURL}}/x?u={{user}}&p={{pass}}"},
		Payloads: PayloadSets{Sets: []PayloadSet{
			{Name: "user", Values: []string{"a", "b", "c"}},
			{Name: "pass", Values: []string{"1", "2", "3"}},
		}},
	}
	got, err := generateHTTPRequests("http://t", cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// every position gets the same value per iteration, from the first set,
	// and it iterates the full set length rather than crossing user x pass.
	want := []string{
		"http://t/x?u=a&p=a", "http://t/x?u=b&p=b", "http://t/x?u=c&p=c",
	}
	urls := reqURLs(got)
	sort.Strings(want)
	if !reflect.DeepEqual(urls, want) {
		t.Errorf("batteringram urls = %v, want %v", urls, want)
	}
	if len(got) != 3 {
		t.Errorf("batteringram sent %d requests, want 3 (set length, not a cross-product)", len(got))
	}
}

func TestStreamRequestsBatteringramCrossesPaths(t *testing.T) {
	cfg := &HTTPConfig{
		Attack: "batteringram",
		Paths:  []string{"{{BaseURL}}/a?p={{payload}}", "{{BaseURL}}/b?p={{payload}}"},
		Payloads: PayloadSets{Sets: []PayloadSet{
			{Name: "payload", Values: []string{"1", "2"}},
		}},
	}
	got, err := generateHTTPRequests("http://t", cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	want := []string{
		"http://t/a?p=1", "http://t/a?p=2", "http://t/b?p=1", "http://t/b?p=2",
	}
	urls := reqURLs(got)
	sort.Strings(want)
	if !reflect.DeepEqual(urls, want) {
		t.Errorf("batteringram urls = %v, want %v", urls, want)
	}
}

func TestStreamRequestsBatteringramEmptySet(t *testing.T) {
	cfg := &HTTPConfig{
		Attack:   "batteringram",
		Paths:    []string{"{{BaseURL}}/"},
		Payloads: PayloadSets{Sets: []PayloadSet{{Name: "payload", Values: nil}}},
	}
	got, err := generateHTTPRequests("http://t", cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty set sent %d requests, want 0", len(got))
	}
}

func TestStreamRequestsHeaderSubstitution(t *testing.T) {
	cfg := &HTTPConfig{
		Paths:   []string{"{{BaseURL}}/"},
		Headers: map[string]string{"X-Token": "t-{{payload}}"},
		Payloads: PayloadSets{Sets: []PayloadSet{
			{Name: "payload", Values: []string{"abc"}},
		}},
	}
	got, err := generateHTTPRequests("http://t", cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(got) != 1 || got[0].Headers["X-Token"] != "t-abc" {
		t.Errorf("header not substituted: %+v", got[0].Headers)
	}
}

func TestExecuteHTTPModuleBudgetTruncates(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// 10 x 10 = 100 combinations, capped at 15.
	users := make([]string, 10)
	passes := make([]string, 10)
	for i := range users {
		users[i] = string(rune('a' + i))
		passes[i] = string(rune('0' + i))
	}
	def := &YAMLModule{
		ID:   "fz",
		Type: TypeHTTP,
		HTTP: &HTTPConfig{
			Paths: []string{"{{BaseURL}}/?u={{user}}&p={{pass}}"},
			Payloads: PayloadSets{Sets: []PayloadSet{
				{Name: "user", Values: users},
				{Name: "pass", Values: passes},
			}},
			Matchers: []Matcher{{Type: "word", Part: "body", Words: []string{"ok"}}},
		},
	}
	opts := Options{Timeout: testTimeout, Client: httpx.Client(testTimeout), FuzzMaxRequests: 15}
	if _, err := ExecuteHTTPModule(context.Background(), srv.URL, def, opts); err != nil {
		t.Fatalf("ExecuteHTTPModule: %v", err)
	}
	if got := atomic.LoadInt64(&hits); got != 15 {
		t.Errorf("sent %d requests, want 15 (budget cap)", got)
	}
}

func TestExecuteHTTPModuleBudgetUnlimited(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	def := &YAMLModule{
		ID:   "fz",
		Type: TypeHTTP,
		HTTP: &HTTPConfig{
			Paths:    []string{"{{BaseURL}}/?p={{payload}}"},
			Payloads: legacyPayloads([]string{"1", "2", "3", "4", "5"}),
			Matchers: []Matcher{{Type: "word", Part: "body", Words: []string{"ok"}}},
		},
	}
	opts := Options{Timeout: testTimeout, Client: httpx.Client(testTimeout), FuzzMaxRequests: 0}
	if _, err := ExecuteHTTPModule(context.Background(), srv.URL, def, opts); err != nil {
		t.Fatalf("ExecuteHTTPModule: %v", err)
	}
	if got := atomic.LoadInt64(&hits); got != 5 {
		t.Errorf("sent %d requests, want 5 (0 = unlimited)", got)
	}
}

// TestExecuteHTTPModuleCancelMidStream is a regression guard for the fan-out
// pool's two send-selects (producer -> reqCh, worker -> resultCh in
// ExecuteHTTPModule). TestExecuteHTTPModuleContextCancel only ever passes an
// already-cancelled context, so the producer returns at its up-front ctx.Err()
// check and never reaches `select { case <-ctx.Done(): case reqCh <- req: }`.
// Here the context is cancelled *while* requests are in flight: the server
// blocks on the request's context so workers sit parked mid-request, the
// producer keeps trying to push a large payload set through an unbuffered
// reqCh with only 2 workers draining it, and cancel has to land on the
// producer's send-select (not just the worker's). If either escape-hatch were
// ever removed, this test would hang and fail via the time.After branch below
// - there is no red phase, since the production code is already correct.
func TestExecuteHTTPModuleCancelMidStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	payloads := make([]string, 200)
	for i := range payloads {
		payloads[i] = string(rune('a'+(i%26))) + string(rune('0'+(i%10)))
	}
	def := &YAMLModule{
		ID:   "fz-cancel-mid",
		Type: TypeHTTP,
		HTTP: &HTTPConfig{
			Paths:    []string{"{{BaseURL}}/?p={{payload}}"},
			Payloads: legacyPayloads(payloads),
			Matchers: []Matcher{{Type: "word", Part: "body", Words: []string{"ok"}}},
		},
	}
	opts := Options{Timeout: testTimeout, Client: httpx.Client(testTimeout), Threads: 2, FuzzMaxRequests: 0}

	before := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(75 * time.Millisecond)
		cancel()
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := ExecuteHTTPModule(ctx, srv.URL, def, opts); err != nil {
			t.Errorf("ExecuteHTTPModule: %v", err)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ExecuteHTTPModule did not return promptly after mid-stream cancel")
	}

	// poll for goroutines to drain rather than a single fixed sleep, so a
	// slow teardown on a loaded runner does not read as a leak.
	deadline := time.Now().Add(2 * time.Second)
	for {
		runtime.GC()
		after := runtime.NumGoroutine()
		if after <= before+2 {
			break
		}
		if time.Now().After(deadline) {
			t.Errorf("possible goroutine leak: before=%d after=%d", before, after)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPayloadSetsUnmarshalRejectsBadShapes(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{"scalar payloads", "payloads: \"admin\"\n"},
		{"named set is a mapping", "payloads:\n  user:\n    a: b\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := yaml.Unmarshal([]byte(tt.src), &HTTPConfig{}); err == nil {
				t.Errorf("%s accepted; want a shape error", tt.name)
			}
		})
	}
}

func TestStreamRequestsEmptySetYieldsNothing(t *testing.T) {
	// an empty set makes the clusterbomb product empty; the generator must send
	// nothing rather than substitute a blank value into every request.
	cfg := &HTTPConfig{
		Paths: []string{"{{BaseURL}}/x?u={{user}}&p={{pass}}"},
		Payloads: PayloadSets{Sets: []PayloadSet{
			{Name: "user", Values: []string{"a", "b"}},
			{Name: "pass", Values: nil},
		}},
	}
	got, err := generateHTTPRequests("http://t", cfg)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty payload set produced %d requests (%v), want none", len(got), reqURLs(got))
	}
}

// fuzzBudgetModule builds a distinct HTTP fuzz module with its own payload
// set, all sharing one target server, for the global-budget tests below.
// fuzzBudgetModule builds a distinct HTTP fuzz module with its own payload set.
func fuzzBudgetModule(id string, n int) *YAMLModule {
	vals := make([]string, n)
	for i := range vals {
		vals[i] = string(rune('a'+(i%26))) + string(rune('0'+(i%10))) + string(rune('A'+(i%26)))
	}
	return &YAMLModule{
		ID:   id,
		Type: TypeHTTP,
		HTTP: &HTTPConfig{
			Paths:    []string{"{{BaseURL}}/?p={{payload}}"},
			Payloads: legacyPayloads(vals),
			Matchers: []Matcher{{Type: "word", Part: "body", Words: []string{"ok"}}},
		},
	}
}

// two modules with no per-module cap, run concurrently, must together send
// exactly the global budget's worth of requests, not per module.
func TestFuzzBudgetCapsAcrossConcurrentModules(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	budget := NewFuzzBudget(30)
	opts := Options{
		Timeout:          testTimeout,
		Client:           httpx.Client(testTimeout),
		FuzzMaxRequests:  0, // unlimited per module: the global budget is the only cap in play
		FuzzGlobalBudget: budget,
	}

	modA := fuzzBudgetModule("fz-a", 100)
	modB := fuzzBudgetModule("fz-b", 100)

	var wg sync.WaitGroup
	wg.Add(2)
	for _, m := range []*YAMLModule{modA, modB} {
		m := m
		go func() {
			defer wg.Done()
			if _, err := ExecuteHTTPModule(context.Background(), srv.URL, m, opts); err != nil {
				t.Errorf("ExecuteHTTPModule(%s): %v", m.ID, err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&hits); got != 30 {
		t.Errorf("sent %d requests across both modules, want 30 (shared global budget)", got)
	}
}

// a budget exhausted mid-stream, shared by several concurrent modules, must
// not deadlock; every ExecuteHTTPModule call returns promptly.
func TestFuzzBudgetExhaustionNoDeadlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	budget := NewFuzzBudget(5)
	opts := Options{
		Timeout:          testTimeout,
		Client:           httpx.Client(testTimeout),
		Threads:          4,
		FuzzGlobalBudget: budget,
	}

	const numModules = 6
	mods := make([]*YAMLModule, numModules)
	for i := range mods {
		mods[i] = fuzzBudgetModule(string(rune('A'+i)), 50)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		wg.Add(numModules)
		for _, m := range mods {
			m := m
			go func() {
				defer wg.Done()
				if _, err := ExecuteHTTPModule(context.Background(), srv.URL, m, opts); err != nil {
					t.Errorf("ExecuteHTTPModule(%s): %v", m.ID, err)
				}
			}()
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("modules did not return after global budget exhaustion; possible deadlock")
	}
}

// a caller that never sets Options.FuzzGlobalBudget keeps seeing unlimited.
func TestFuzzBudgetNilIsUnlimited(t *testing.T) {
	var b *FuzzBudget
	for i := 0; i < 1000; i++ {
		if !b.Reserve() {
			t.Fatalf("nil budget refused reservation %d, want always true", i)
		}
	}
}

// TestNewFuzzBudgetUnlimited pins the nil-means-unlimited contract from both
// ends: the constructor returns nil for a non-positive cap, and a nil budget
// keeps reserving forever. A nil check missing from Reserve would panic on
// every scan run with the flag set to 0.
func TestNewFuzzBudgetUnlimited(t *testing.T) {
	for _, max := range []int{0, -1, -1000} {
		if b := NewFuzzBudget(max); b != nil {
			t.Errorf("NewFuzzBudget(%d) = %+v, want nil (unlimited)", max, b)
		}
	}

	var unlimited *FuzzBudget
	for i := 0; i < 1000; i++ {
		if !unlimited.Reserve() {
			t.Fatalf("nil budget refused a reservation at attempt %d", i+1)
		}
	}

	limited := NewFuzzBudget(2)
	for i := 1; i <= 2; i++ {
		if !limited.Reserve() {
			t.Fatalf("budget of 2 refused reservation %d", i)
		}
	}
	if limited.Reserve() {
		t.Error("budget of 2 allowed a third reservation")
	}
}
