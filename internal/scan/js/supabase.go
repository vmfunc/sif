/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

// todo: scan for storage and auth vulns

package js

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
)

// jwtRegex matches JWT tokens in JavaScript content.
var jwtRegex = regexp.MustCompile(`["'\x60](ey[A-Za-z0-9_-]{2,}(?:\.[A-Za-z0-9_-]{2,}){2})["'\x60]`)

type supabaseJwtBody struct {
	ProjectId *string `json:"ref"`
	Role      *string `json:"role"`
}

type supabaseScanResult struct {
	ProjectId   string               `json:"project_id"`
	ApiKey      string               `json:"api_key"`
	Role        string               `json:"role"` // note: if this isnt anon its bad
	Collections []supabaseCollection `json:"collections"`
}

type supabaseCollection struct {
	Name   string            `json:"name"`
	Sample []json.RawMessage `json:"sample"` // raw JSON for deferred parsing
	Count  int               `json:"count"`
}

// supabaseArrayResponse represents a response that is an array with count header.
type supabaseArrayResponse struct {
	Array []json.RawMessage
	Count int
}

// supabaseAuthResponse represents the auth response from Supabase.
type supabaseAuthResponse struct {
	AccessToken string `json:"access_token"`
}

// supabaseOpenAPIResponse represents the OpenAPI spec response.
type supabaseOpenAPIResponse struct {
	Paths map[string]json.RawMessage `json:"paths"`
}

// getSupabaseArrayResponse fetches a Supabase endpoint that returns an array.
func getSupabaseArrayResponse(projectId, path, apikey string, auth *string) (*supabaseArrayResponse, error) {
	body, resp, err := doSupabaseRequest(projectId, path, apikey, auth) //nolint:bodyclose // closed in doSupabaseRequest
	if err != nil {
		return nil, err
	}

	var arr []json.RawMessage
	if err := json.Unmarshal(body, &arr); err != nil {
		return nil, err
	}

	contentRange := resp.Header.Get("Content-Range")
	parts := strings.Split(contentRange, "/")
	if len(parts) < 2 {
		return nil, errors.New("invalid Content-Range header")
	}
	count, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}

	return &supabaseArrayResponse{Array: arr, Count: count}, nil
}

// getSupabaseOpenAPI fetches the OpenAPI spec from Supabase.
func getSupabaseOpenAPI(projectId, apikey string, auth *string) (*supabaseOpenAPIResponse, error) {
	body, _, err := doSupabaseRequest(projectId, "/rest/v1/", apikey, auth) //nolint:bodyclose // closed in doSupabaseRequest
	if err != nil {
		return nil, err
	}

	var spec supabaseOpenAPIResponse
	if err := json.Unmarshal(body, &spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

// doSupabaseRequest performs a GET request to the Supabase API.
func doSupabaseRequest(projectId, path, apikey string, auth *string) ([]byte, *http.Response, error) {
	client := http.Client{}

	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, "https://"+projectId+".supabase.co"+path, http.NoBody)
	if err != nil {
		return nil, nil, err
	}

	log.Debugf("Sending request to %s", req.URL.String())
	req.Header.Set("apikey", apikey)
	req.Header.Set("Prefer", "count=exact")
	if auth != nil {
		req.Header.Set("Authorization", "Bearer "+*auth)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, nil, errors.New("request to " + resp.Request.URL.String() + " failed with status code " + strconv.Itoa(resp.StatusCode))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, nil, err
	}

	return body, resp, nil
}

func ScanSupabase(jsContent string, jsUrl string) ([]supabaseScanResult, error) {
	supabaselog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "🚧 JavaScript > Supabase ⚡️",
	}).With("url", jsUrl)

	var results = []supabaseScanResult{}
	jwtGroups := jwtRegex.FindAllStringSubmatch(jsContent, -1)

	var jwts = []string{}

	for _, jwtGroup := range jwtGroups {
		jwts = append(jwts, jwtGroup[1])
	}

	slices.Sort(jwts)
	jwts = slices.Compact(jwts)

	for _, jwt := range jwts {
		parts := strings.Split(jwt, ".")
		body := parts[1]

		decoded, err := base64.RawStdEncoding.DecodeString(body)
		if err != nil {
			supabaselog.Debugf("Failed to decode JWT %s: %s", body, err)
			continue
		}

		supabaselog.Debugf("JWT body: %s", decoded)
		var supabaseJwt *supabaseJwtBody
		err = json.Unmarshal(decoded, &supabaseJwt)
		if err != nil {
			supabaselog.Debugf("Failed to json parse JWT %s: %s", jwt, err)
			continue
		}

		if supabaseJwt.ProjectId == nil || supabaseJwt.Role == nil {
			continue
		}

		supabaselog.Infof("Found valid supabase project %s with role %s", *supabaseJwt.ProjectId, *supabaseJwt.Role)
		client := http.Client{}

		req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost, "https://"+*supabaseJwt.ProjectId+".supabase.co/auth/v1/signup", bytes.NewBufferString(`{"email":"automated`+strconv.Itoa(int(time.Now().Unix()))+`@sif.sh","password":"automatedacct"}`))
		if err != nil {
			supabaselog.Errorf("Error while creating HTTP req for creating user: %s", err)
			continue
		}
		req.Header.Set("apikey", jwt)

		resp, err := client.Do(req)
		if err != nil {
			supabaselog.Errorf("Error while sending request to create user: %s", err)
			continue
		}

		var auth string
		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
			if err != nil {
				resp.Body.Close()
				return nil, err
			}
			resp.Body.Close()

			var authResp supabaseAuthResponse
			if err := json.Unmarshal(body, &authResp); err != nil {
				return nil, err
			}

			auth = authResp.AccessToken
			supabaselog.Infof("Created account with JWT %s", auth)
		} else {
			resp.Body.Close()
		}

		var collections = []supabaseCollection{}

		openAPI, err := getSupabaseOpenAPI(*supabaseJwt.ProjectId, jwt, &auth)
		if err != nil {
			return nil, err
		}

		if openAPI.Paths == nil {
			return nil, errors.New("paths not found in supabase openapi")
		}

		for path := range openAPI.Paths {
			if path == "/" {
				continue
			}

			// todo: support for scanning rpc calls
			if strings.HasPrefix(path, "/rpc/") {
				continue
			}

			sampleResp, err := getSupabaseArrayResponse(*supabaseJwt.ProjectId, "/rest/v1"+path, jwt, &auth)
			if err != nil {
				continue
			}

			marshalled, err := json.Marshal(sampleResp.Array)
			if err != nil {
				supabaselog.Errorf("Failed to marshal sample data for %s: %s", path, err)
			}

			supabaselog.Infof("Got sample (1000 entries) for collection %s: %s", path, string(marshalled))

			// limit to first 10 samples
			sampleLimit := len(sampleResp.Array)
			if sampleLimit > 10 {
				sampleLimit = 10
			}

			collection := supabaseCollection{
				Name:   strings.TrimPrefix(path, "/"),
				Sample: sampleResp.Array[:sampleLimit], // passed to local LLM for scope
				Count:  sampleResp.Count,
			}

			if collection.Count > 1 /* one entry may just be for the user */ {
				collections = append(collections, collection)
			}
		}

		result := supabaseScanResult{
			ProjectId:   *supabaseJwt.ProjectId,
			ApiKey:      jwt,
			Role:        *supabaseJwt.Role,
			Collections: collections,
		}
		results = append(results, result)
	}

	// todo(eva): implement supabase scanning
	return results, nil
}
