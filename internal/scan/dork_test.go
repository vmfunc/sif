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
	"net/url"
	"strings"
	"testing"
)

// buildSearchURL mirrors how the google-search client turns a search term into
// a request url: it trims spaces, swaps the rest for '+' and drops the term
// into the query string verbatim without any encoding.
func buildSearchURL(term string) string {
	term = strings.Trim(term, " ")
	term = strings.ReplaceAll(term, " ", "+")
	return "https://www.google.com/search?q=" + term + "&hl=en"
}

func TestDorkQueryPreservesSpecialCharacters(t *testing.T) {
	cases := []struct {
		name string
		dork string
	}{
		{"hash", `intext:"#mysql dump" filetype:sql`},
		{"ampersand", `filetype:sql "a & b"`},
		{"question", `inurl:index.php?id=`},
		{"plain", `intitle:"index of" passwd`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.dork + " example.com"

			u, err := url.Parse(buildSearchURL(dorkQuery(tc.dork, "example.com")))
			if err != nil {
				t.Fatalf("parse encoded url: %v", err)
			}
			if got := u.Query().Get("q"); got != want {
				t.Errorf("encoded query = %q, want %q", got, want)
			}
			// a fragment or a stray query param means the dork leaked out of q.
			if u.Fragment != "" {
				t.Errorf("encoded url has fragment %q, query truncated", u.Fragment)
			}
			if len(u.Query()) != 2 { // q and hl only
				t.Errorf("encoded url has stray params: %v", u.Query())
			}
		})
	}
}

// guards the regression directly: the old naive term drops everything after a
// '#' into the fragment, so the search runs against a fragment of the dork.
func TestDorkQueryFixesNaiveTruncation(t *testing.T) {
	dork := `intext:"#mysql dump" filetype:sql`

	naive, err := url.Parse(buildSearchURL(dork + " example.com"))
	if err != nil {
		t.Fatalf("parse naive url: %v", err)
	}
	if naive.Query().Get("q") == dork+" example.com" {
		t.Fatal("expected the naive term to truncate, but it survived")
	}

	fixed, err := url.Parse(buildSearchURL(dorkQuery(dork, "example.com")))
	if err != nil {
		t.Fatalf("parse fixed url: %v", err)
	}
	if got, want := fixed.Query().Get("q"), dork+" example.com"; got != want {
		t.Errorf("fixed query = %q, want %q", got, want)
	}
}
