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

package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// serveFingerprint stands up a loopback server returning body at 200 OK and
// returns its host:port for checkSubdomainTakeover to treat as a live subdomain.
func serveFingerprint(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// a body fingerprint for a service that can-i-take-over-xyz marks "Not
// vulnerable" must not raise a takeover: the provider mitigated the vector, so a
// live page carrying the string is never claimable.
func TestCheckSubdomainTakeover_NotVulnerableServiceNotFlagged(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	mitigated := map[string]string{
		"Fastly":    "Fastly error: unknown domain",
		"Zendesk":   "Help Center Closed",
		"UserVoice": "This UserVoice subdomain is currently available!",
		"Acquia":    "The site you are looking for could not be found.",
	}
	for service, fingerprint := range mitigated {
		subdomain := serveFingerprint(t, "<html><body>"+fingerprint+"</body></html>")
		vulnerable, got, _ := checkSubdomainTakeover(subdomain, client)
		if vulnerable || got != "" {
			t.Errorf("%s fingerprint raised a takeover (vulnerable=%v service=%q); the provider mitigated the vector", service, vulnerable, got)
		}
	}
}

// a still-vulnerable provider's fingerprint keeps firing, so pruning the
// mitigated services does not silently drop real detections.
func TestCheckSubdomainTakeover_VulnerableServiceStillFlagged(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	subdomain := serveFingerprint(t, "<html><body>The specified bucket does not exist</body></html>")
	vulnerable, service, _ := checkSubdomainTakeover(subdomain, client)
	if !vulnerable || service != "Amazon S3" {
		t.Errorf("expected Amazon S3 takeover, got vulnerable=%v service=%q", vulnerable, service)
	}
}

// reproduces the fixed false positive: a body fingerprint whose cname resolves
// elsewhere (or is a plain A record) must not be flagged. the pre-fix live path
// ignored the cname and fired on the body match alone.
func TestCheckSubdomainTakeover_BodySignatureWithoutMatchingCNAMENotConfirmed(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	subdomain := serveFingerprint(t, "<html><body>The specified bucket does not exist</body></html>")

	orig := lookupCNAME
	defer func() { lookupCNAME = orig }()

	// cname resolves, but to something that isn't the s3 apex: the signature
	// match is coincidental, not a dangling delegation.
	lookupCNAME = func(_ context.Context, _ string) (string, error) {
		return "unrelated-app.example.net.", nil
	}

	vulnerable, service, confidence := checkSubdomainTakeover(subdomain, client)
	if vulnerable {
		t.Errorf("expected no takeover when cname does not back the matched provider, got vulnerable=%v service=%q confidence=%q", vulnerable, service, confidence)
	}
}

// when the cname does resolve to the matched provider's apex, the same body
// signature is a confirmed takeover, not just a potential one.
func TestCheckSubdomainTakeover_BodySignatureWithMatchingCNAMEConfirmed(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	subdomain := serveFingerprint(t, "<html><body>The specified bucket does not exist</body></html>")

	orig := lookupCNAME
	defer func() { lookupCNAME = orig }()

	lookupCNAME = func(_ context.Context, _ string) (string, error) {
		return "mybucket.s3.amazonaws.com.", nil
	}

	vulnerable, service, confidence := checkSubdomainTakeover(subdomain, client)
	if !vulnerable || service != "Amazon S3" || confidence != "confirmed" {
		t.Errorf("expected confirmed Amazon S3 takeover, got vulnerable=%v service=%q confidence=%q", vulnerable, service, confidence)
	}
}

// a provider with no cname apex to correlate against (e.g. tumblr) must degrade
// to a low-confidence potential, not be dropped: dropping it would be a false
// negative on a real takeover. see serviceCorrelatable.
func TestCheckSubdomainTakeover_UncorrelatableProviderDegradesToPotential(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	subdomain := serveFingerprint(t, "<html><body>There's nothing here.</body></html>")

	orig := lookupCNAME
	defer func() { lookupCNAME = orig }()

	// host resolves (lookup succeeds), but tumblr has no apex to check against.
	lookupCNAME = func(_ context.Context, _ string) (string, error) {
		return "domains.tumblr.com.", nil
	}

	vulnerable, service, confidence := checkSubdomainTakeover(subdomain, client)
	if !vulnerable || service != "Tumblr" || confidence != "potential" {
		t.Errorf("expected potential Tumblr takeover, got vulnerable=%v service=%q confidence=%q", vulnerable, service, confidence)
	}
}

// removed fingerprints matched generic content, not a provider's unclaimed-domain
// page (none in can-i-take-over-xyz), so must not raise a takeover: activecampaign
// was lighttpd's default page, kajabi/thinkific/tave/teamwork generic "not found".
func TestCheckSubdomainTakeover_GenericFingerprintNotFlagged(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	bogus := map[string]string{
		"lighttpd default page":   `<html><body><img alt="LIGHTTPD - fly light." src="light.png"></body></html>`,
		"generic 404 (kajabi)":    "<html><body>The page you were looking for doesn't exist.</body></html>",
		"generic 404 (thinkific)": "<html><body>You may have mistyped the address or the page may have moved.</body></html>",
		"generic 404 (tave)":      "<html><body>Sorry, this page is no longer available.</body></html>",
		"generic 404 (teamwork)":  "<html><body>Oops - We didn't find your site.</body></html>",
	}
	for name, body := range bogus {
		subdomain := serveFingerprint(t, body)
		vulnerable, service, _ := checkSubdomainTakeover(subdomain, client)
		if vulnerable || service != "" {
			t.Errorf("%s raised a takeover (vulnerable=%v service=%q); it matches generic content, not an unclaimed-domain page", name, vulnerable, service)
		}
	}
}
