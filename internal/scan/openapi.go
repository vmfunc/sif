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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	charmlog "github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/httpx"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/output"
	"gopkg.in/yaml.v3"
)

// OpenAPIResult is the parsed spec exposure plus the endpoints enumerated from
// it.
type OpenAPIResult struct {
	SpecURL   string            `json:"spec_url"`  // the path the spec was served at
	Title     string            `json:"title"`     // info.title from the spec
	Version   string            `json:"version"`   // openapi/swagger version string
	Endpoints []OpenAPIEndpoint `json:"endpoints"` // every path+method pair
	Severity  string            `json:"severity"`  // exposure severity
}

// OpenAPIEndpoint is one path+method, flagged when nothing in the spec gates it.
type OpenAPIEndpoint struct {
	Path   string `json:"path"`
	Method string `json:"method"`
	Unauth bool   `json:"unauth"` // no security requirement on this operation
}

// openapiSpecPaths are the conventional locations a spec is served from. ordered
// most-common first so the typical hit is found early.
var openapiSpecPaths = []string{
	"/swagger.json",
	"/openapi.json",
	"/v3/api-docs",
	"/api-docs",
	"/swagger/v1/swagger.json",
	"/swagger-ui/",
}

// openapiBodyReadCap bounds spec body reads. specs are text and rarely huge, but
// an attacker-controlled endpoint could stream forever, so cap it.
const openapiBodyReadCap = 8 << 20

// the http methods an openapi path item can declare. anything outside this set
// is metadata (parameters, summary), not an operation.
var openapiHTTPMethods = []string{
	http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete,
	http.MethodOptions, http.MethodHead, http.MethodPatch, http.MethodTrace,
}

// exposure severities. an enumerable spec is medium on its own; unauthenticated
// operations bump it to high.
const (
	openapiSevMedium = "medium"
	openapiSevHigh   = "high"
)

// openapiSpec is the minimal slice of an openapi/swagger document we care about:
// the version banner, info block, top-level security and the path map. unknown
// fields are ignored by both json and yaml decoders.
type openapiSpec struct {
	OpenAPI  string                       `json:"openapi" yaml:"openapi"`
	Swagger  string                       `json:"swagger" yaml:"swagger"`
	Info     openapiInfo                  `json:"info" yaml:"info"`
	Security []map[string][]string        `json:"security" yaml:"security"`
	Paths    map[string]map[string]rawOps `json:"paths" yaml:"paths"`
}

type openapiInfo struct {
	Title   string `json:"title" yaml:"title"`
	Version string `json:"version" yaml:"version"`
}

// rawOps captures just the per-operation security block so we can tell whether
// an operation requires auth. the rest of the operation object is irrelevant.
type rawOps struct {
	Security []map[string][]string `json:"security" yaml:"security"`
}

// OpenAPI probes the candidate spec paths concurrently and, on the first hit,
// parses the spec and enumerates its endpoints.
func OpenAPI(targetURL string, timeout time.Duration, threads int, logdir string) (*OpenAPIResult, error) {
	log := output.Module("OPENAPI")
	log.Start()

	spin := output.NewSpinner("Probing for exposed openapi/swagger specs")
	spin.Start()

	sanitizedURL := stripScheme(targetURL)

	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, "OpenAPI/Swagger spec exposure"); err != nil {
			spin.Stop()
			log.Error("error creating log file: %v", err)
			return nil, fmt.Errorf("create openapi log: %w", err)
		}
	}

	client := httpx.Client(timeout)
	base := strings.TrimRight(targetURL, "/")

	result := probeOpenAPIPaths(client, base, threads)

	spin.Stop()

	if result == nil {
		log.Info("no openapi/swagger spec exposed")
		log.Complete(0, "found")
		return nil, nil //nolint:nilnil // no exposed spec is not an error
	}

	unauth := 0
	for i := 0; i < len(result.Endpoints); i++ {
		if result.Endpoints[i].Unauth {
			unauth++
		}
	}

	log.Warn("openapi %s: spec at %s exposes %d endpoints (%d unauthenticated)",
		renderOpenAPISeverity(result.Severity),
		output.Highlight.Render(result.SpecURL),
		len(result.Endpoints), unauth)

	if logdir != "" {
		_ = logger.Write(sanitizedURL, logdir,
			fmt.Sprintf("OpenAPI spec exposed at %s: %d endpoints, %d unauthenticated\n",
				result.SpecURL, len(result.Endpoints), unauth))
	}

	log.Complete(len(result.Endpoints), "endpoints")
	return result, nil
}

// probeOpenAPIPaths fans the candidate paths across a worker pool and returns the
// first parseable spec. the first hit wins, so once one worker fills the result
// the rest of the channel drains without re-parsing.
func probeOpenAPIPaths(client *http.Client, base string, threads int) *OpenAPIResult {
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		result *OpenAPIResult
	)

	pathChan := make(chan string, len(openapiSpecPaths))
	for i := 0; i < len(openapiSpecPaths); i++ {
		pathChan <- openapiSpecPaths[i]
	}
	close(pathChan)

	wg.Add(threads)
	for t := 0; t < threads; t++ {
		go func() {
			defer wg.Done()
			for path := range pathChan {
				// a spec already landed; stop spending requests.
				mu.Lock()
				done := result != nil
				mu.Unlock()
				if done {
					return
				}

				hit := fetchOpenAPISpec(client, base+path)
				if hit == nil {
					continue
				}
				hit.SpecURL = base + path

				mu.Lock()
				if result == nil {
					result = hit
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	return result
}

// fetchOpenAPISpec GETs one candidate path and parses the body as a spec. it
// returns nil on any failure (non-200, unparseable, zero paths) so a swagger-ui
// html page or a 404 doesn't masquerade as a finding.
func fetchOpenAPISpec(client *http.Client, specURL string) *OpenAPIResult {
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, specURL, http.NoBody)
	if err != nil {
		charmlog.Debugf("openapi: build request for %s: %v", specURL, err)
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		charmlog.Debugf("openapi: request %s: %v", specURL, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, openapiBodyReadCap))
	if err != nil {
		charmlog.Debugf("openapi: read %s: %v", specURL, err)
		return nil
	}

	spec, ok := parseOpenAPISpec(body)
	if !ok {
		return nil
	}

	return specToResult(spec)
}

// parseOpenAPISpec decodes the body as json first, then yaml. it only accepts a
// document that actually declares an openapi/swagger version and at least one
// path, so an unrelated json/yaml file served at the candidate path is rejected.
func parseOpenAPISpec(body []byte) (*openapiSpec, bool) {
	var spec openapiSpec
	if err := json.Unmarshal(body, &spec); err != nil {
		if err := yaml.Unmarshal(body, &spec); err != nil {
			return nil, false
		}
	}

	versioned := spec.OpenAPI != "" || spec.Swagger != ""
	if !versioned || len(spec.Paths) == 0 {
		return nil, false
	}
	return &spec, true
}

// specToResult flattens the parsed spec into enumerated endpoints and ranks the
// exposure. an operation with no security requirement (and no top-level default)
// is flagged unauthenticated, which bumps the overall severity to high.
func specToResult(spec *openapiSpec) *OpenAPIResult {
	hasGlobalSecurity := len(spec.Security) > 0

	endpoints := make([]OpenAPIEndpoint, 0, len(spec.Paths))
	anyUnauth := false

	// stable order: sort paths so the report is deterministic across runs.
	paths := make([]string, 0, len(spec.Paths))
	for p := range spec.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for i := 0; i < len(paths); i++ {
		path := paths[i]
		ops := spec.Paths[path]
		for j := 0; j < len(openapiHTTPMethods); j++ {
			method := openapiHTTPMethods[j]
			op, ok := ops[strings.ToLower(method)]
			if !ok {
				continue
			}
			// an operation is unauth when neither it nor the global default
			// declares a security requirement.
			unauth := len(op.Security) == 0 && !hasGlobalSecurity
			if unauth {
				anyUnauth = true
			}
			endpoints = append(endpoints, OpenAPIEndpoint{
				Path:   path,
				Method: method,
				Unauth: unauth,
			})
		}
	}

	severity := openapiSevMedium
	if anyUnauth {
		severity = openapiSevHigh
	}

	version := spec.OpenAPI
	if version == "" {
		version = spec.Swagger
	}

	return &OpenAPIResult{
		Title:     spec.Info.Title,
		Version:   version,
		Endpoints: endpoints,
		Severity:  severity,
	}
}

func renderOpenAPISeverity(severity string) string {
	if severity == openapiSevHigh {
		return output.SeverityHigh.Render(severity)
	}
	return output.SeverityMedium.Render(severity)
}

// ResultType identifies openapi findings for the result registry.
func (r *OpenAPIResult) ResultType() string { return "openapi" }

var _ ScanResult = (*OpenAPIResult)(nil)
