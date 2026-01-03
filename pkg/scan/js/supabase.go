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
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
)

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
	Name   string        `json:"name"`
	Sample []interface{} `json:"sample"`
	Count  int           `json:"count"`
}

func GetSupabaseJsonResponse(projectId string, path string, apikey string, auth *string) (map[string]interface{}, error) {
	client := http.Client{}

	req, err := http.NewRequest("GET", "https://"+projectId+".supabase.co"+path, nil)
	if err != nil {
		return nil, err
	}

	log.Debugf("Sending request to %s", req.URL.String())
	req.Header.Set("apikey", apikey)
	req.Header.Set("Prefer", "count=exact")
	if auth != nil {
		req.Header.Set("Authorization", "Bearer "+*auth)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New("Request to " + resp.Request.URL.String() + " failed with status code " + strconv.Itoa(resp.StatusCode))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	content := string(body)

	var data interface{}

	err = json.Unmarshal([]byte(content), &data)
	if err != nil {
		return nil, err
	}

	arr, ok := data.([]interface{})
	if ok {
		wrappedData := map[string]interface{}{}

		contentRange := resp.Header.Get("Content-Range")
		count, err := strconv.Atoi(strings.Split(contentRange, "/")[1])
		if err != nil {
			return nil, err
		}

		wrappedData["count"] = count
		wrappedData["array"] = arr

		return wrappedData, nil
	}

	return data.(map[string]interface{}), nil
}

func ScanSupabase(jsContent string, jsUrl string) ([]supabaseScanResult, error) {
	supabaselog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "🚧 JavaScript > Supabase ⚡️",
	}).With("url", jsUrl)

	jwtRegex, err := regexp.Compile("[\"|'|`](ey[A-Za-z0-9_-]{2,}(?:\\.[A-Za-z0-9_-]{2,}){2})[\"|'|`]")

	if err != nil {
		return nil, err
	}

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
		err = json.Unmarshal([]byte(decoded), &supabaseJwt)
		if err != nil {
			supabaselog.Debugf("Failed to json parse JWT %s: %s", jwt, err)
			continue
		}

		if supabaseJwt.ProjectId == nil || supabaseJwt.Role == nil {
			continue
		}

		supabaselog.Infof("Found valid supabase project %s with role %s", *supabaseJwt.ProjectId, *supabaseJwt.Role)
		client := http.Client{}

		req, err := http.NewRequest("POST", "https://"+*supabaseJwt.ProjectId+".supabase.co/auth/v1/signup", bytes.NewBufferString(`{"email":"automated`+strconv.Itoa(int(time.Now().Unix()))+`@sif.sh","password":"automatedacct"}`))
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
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			content := string(body)

			var data map[string]interface{}
			err = json.Unmarshal([]byte(content), &data)
			if err != nil {
				return nil, err
			}

			auth = data["access_token"].(string)
			supabaselog.Infof("Created account with JWT %s", auth)
		}

		var collections = []supabaseCollection{}

		res, err := GetSupabaseJsonResponse(*supabaseJwt.ProjectId, "/rest/v1/", jwt, &auth)
		if err != nil {
			return nil, err
		}

		index := res

		if index["paths"] == nil {
			return nil, errors.New("paths not found in supabase openapi")
		}

		var paths = index["paths"].(map[string]interface{})

		for k := range paths {
			if k == "/" {
				continue
			}

			// todo: support for scanning rpc calls
			if strings.HasPrefix(k, "/rpc/") {
				continue
			}

			sampleObj, err := GetSupabaseJsonResponse(*supabaseJwt.ProjectId, "/rest/v1"+k, jwt, &auth)
			if err != nil {
				continue
			}

			samples := sampleObj["array"].([]interface{})
			marshalled, err := json.Marshal(samples)
			if err != nil {
				supabaselog.Errorf("Failed to marshal sample data for %s: %s", k, err)
			}

			supabaselog.Infof("Got sample (1000 entries) for collection %s: %s", k, string(marshalled))

			limitedSample := samples[0:int(math.Min(float64(len(samples)), 10))]

			collection := supabaseCollection{
				Name:   strings.TrimPrefix(k, "/"),
				Sample: limitedSample, // passed to local LLM for scope
				Count:  sampleObj["count"].(int),
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
