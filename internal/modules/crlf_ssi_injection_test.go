package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

const (
	crlfModule = "../../modules/http/crlf-injection.yaml"
	ssiModule  = "../../modules/http/ssi-injection.yaml"
)

func runInjectionModule(t *testing.T, file string, h http.Handler) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule(file)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	res, err := modules.ExecuteHTTPModule(context.Background(), srv.URL, def, modules.Options{
		Timeout: 5 * time.Second,
		Threads: 4,
	})
	if err != nil {
		t.Fatalf("execute %s: %v", file, err)
	}
	return res
}

// crlfHandler simulates a server that reflects request-supplied values into the
// response header block. When sanitize is false it splits any value on CR/LF and
// promotes trailing "Key: Value" lines to real headers, reproducing response
// splitting. When sanitize is true it strips CR/LF first, so no header materializes.
func crlfHandler(sanitize bool) http.HandlerFunc {
	newline := regexp.MustCompile(`\r\n|\r|\n`)
	return func(w http.ResponseWriter, r *http.Request) {
		var vals []string
		for _, vv := range r.URL.Query() {
			vals = append(vals, vv...)
		}
		vals = append(vals, r.URL.Path)

		for _, v := range vals {
			if sanitize {
				v = strings.NewReplacer("\r", "", "\n", "").Replace(v)
			}
			segs := newline.Split(v, -1)
			if len(segs) < 2 {
				continue
			}
			for _, seg := range segs[1:] {
				idx := strings.Index(seg, ":")
				if idx <= 0 {
					continue
				}
				w.Header().Set(strings.TrimSpace(seg[:idx]), strings.TrimSpace(seg[idx+1:]))
			}
		}
		_, _ = w.Write([]byte("ok"))
	}
}

// ssiHandler simulates SSI processing of reflected input. When render is true it
// replaces an echo directive with a live GMT date (as Apache mod_include would),
// consuming the directive. When render is false it echoes the value literally.
func ssiHandler(render bool) http.HandlerFunc {
	directive := regexp.MustCompile(`<!--#echo var="[A-Z_]+"-->`)
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		if render {
			v = directive.ReplaceAllString(v, "Wednesday, 08-Jul-2026 14:30:00 GMT")
		}
		_, _ = w.Write([]byte("<html><body>" + v + "</body></html>"))
	}
}

// ssiEntityHandler reflects the decoded value but HTML-encodes the metacharacters
// with NUMERIC character references ("<" -> "&#60;"). This is the adversarial
// case: the escape itself carries digits with no literal "<", which a naive
// "[^<]*\d[^<]*" regex would wrongly match.
func ssiEntityHandler() http.HandlerFunc {
	rep := strings.NewReplacer("<", "&#60;", ">", "&#62;", "\"", "&#34;")
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>" + rep.Replace(r.URL.Query().Get("q")) + "</body></html>"))
	}
}

// ssiRawHandler reflects the RAW (still percent-encoded) query value, as an app
// that echoes the query string verbatim would ("no results for %3C..."). The
// "%3C" escapes carry digits with no literal "<".
func ssiRawHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.RawQuery
		if i := strings.IndexByte(raw, '='); i >= 0 {
			raw = raw[i+1:]
		}
		if i := strings.IndexByte(raw, '&'); i >= 0 {
			raw = raw[:i]
		}
		_, _ = w.Write([]byte("<html><body>no results for " + raw + "</body></html>"))
	}
}

func TestCRLFInjectionModule(t *testing.T) {
	t.Run("injected header materializes", func(t *testing.T) {
		res := runInjectionModule(t, crlfModule, crlfHandler(false))
		if len(res.Findings) == 0 {
			t.Fatal("expected a crlf finding when the injected header is reflected")
		}
	})

	t.Run("sanitized response is not flagged", func(t *testing.T) {
		res := runInjectionModule(t, crlfModule, crlfHandler(true))
		if len(res.Findings) != 0 {
			t.Fatalf("got %d findings on a sanitizing server, want 0", len(res.Findings))
		}
	})

	t.Run("body-only reflection is not flagged", func(t *testing.T) {
		echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(r.URL.RawQuery))
		})
		res := runInjectionModule(t, crlfModule, echo)
		if len(res.Findings) != 0 {
			t.Fatalf("got %d findings on body-only reflection, want 0", len(res.Findings))
		}
	})

	// a non-splitting server that echoes the param into an unrelated header
	// value: go collapses the CR/LF so no header line is added, but the literal
	// "X-Sif-Injected" text survives inside that value. a line-anchored matcher
	// must not treat that mid-line text as an injected header.
	t.Run("header-value reflection is not flagged", func(t *testing.T) {
		reflect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, vv := range r.URL.Query() {
				for _, v := range vv {
					w.Header().Set("X-Echo-Request", v)
				}
			}
			_, _ = w.Write([]byte("ok"))
		})
		res := runInjectionModule(t, crlfModule, reflect)
		if len(res.Findings) != 0 {
			t.Fatalf("got %d findings on header-value reflection, want 0", len(res.Findings))
		}
	})
}

func TestSSIInjectionModule(t *testing.T) {
	t.Run("rendered directive is flagged", func(t *testing.T) {
		res := runInjectionModule(t, ssiModule, ssiHandler(true))
		if len(res.Findings) == 0 {
			t.Fatal("expected an ssi finding when the echo directive renders a date")
		}
	})

	t.Run("literal echo is not flagged", func(t *testing.T) {
		res := runInjectionModule(t, ssiModule, ssiHandler(false))
		if len(res.Findings) != 0 {
			t.Fatalf("got %d findings when the directive is echoed literally, want 0", len(res.Findings))
		}
	})

	t.Run("numeric-entity reflection is not flagged", func(t *testing.T) {
		res := runInjectionModule(t, ssiModule, ssiEntityHandler())
		if len(res.Findings) != 0 {
			t.Fatalf("got %d findings on numeric-entity reflection, want 0", len(res.Findings))
		}
	})

	t.Run("raw percent reflection is not flagged", func(t *testing.T) {
		res := runInjectionModule(t, ssiModule, ssiRawHandler())
		if len(res.Findings) != 0 {
			t.Fatalf("got %d findings on raw percent-encoded reflection, want 0", len(res.Findings))
		}
	})

	// literal reflection plus a digit elsewhere on the page: the "<" of the
	// echoed directive sits between the markers, so no cross-sentinel match.
	t.Run("reflection with unrelated digit is not flagged", func(t *testing.T) {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<p>page 7</p>" + r.URL.Query().Get("q")))
		})
		res := runInjectionModule(t, ssiModule, h)
		if len(res.Findings) != 0 {
			t.Fatalf("got %d findings on reflection beside an unrelated digit, want 0", len(res.Findings))
		}
	})
}
