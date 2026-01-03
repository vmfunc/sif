/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (Celeste Hickenlooper), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package scan

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectLFIFromResponse_EtcPasswd(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		expectFound bool
		expectDesc  string
	}{
		{
			name:        "root entry",
			body:        "root:x:0:0:root:/root:/bin/bash",
			expectFound: true,
			expectDesc:  "/etc/passwd content",
		},
		{
			name:        "daemon entry",
			body:        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
			expectFound: true,
			expectDesc:  "/etc/passwd content",
		},
		{
			name:        "nobody entry",
			body:        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
			expectFound: true,
			expectDesc:  "/etc/passwd content",
		},
		{
			name:        "no evidence",
			body:        "<html><body>Hello World</body></html>",
			expectFound: false,
			expectDesc:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, desc := DetectLFIFromResponse(tt.body)
			if found != tt.expectFound {
				t.Errorf("DetectLFIFromResponse() found = %v, want %v", found, tt.expectFound)
			}
			if desc != tt.expectDesc {
				t.Errorf("DetectLFIFromResponse() desc = %v, want %v", desc, tt.expectDesc)
			}
		})
	}
}

func TestDetectLFIFromResponse_WindowsFiles(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		expectFound bool
	}{
		{
			name:        "boot.ini boot loader",
			body:        "[boot loader]\ntimeout=30",
			expectFound: true,
		},
		{
			name:        "boot.ini operating systems",
			body:        "[operating systems]\nmulti(0)",
			expectFound: true,
		},
		{
			name:        "win.ini fonts section",
			body:        "; for 16-bit app support\n[fonts]",
			expectFound: true,
		},
		{
			name:        "hosts file",
			body:        "127.0.0.1   localhost",
			expectFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, _ := DetectLFIFromResponse(tt.body)
			if found != tt.expectFound {
				t.Errorf("DetectLFIFromResponse() found = %v, want %v", found, tt.expectFound)
			}
		})
	}
}

func TestDetectLFIFromResponse_EnvironmentVars(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		expectFound bool
	}{
		{
			name:        "DOCUMENT_ROOT",
			body:        "DOCUMENT_ROOT=/var/www/html",
			expectFound: true,
		},
		{
			name:        "PATH variable",
			body:        "PATH=/usr/local/bin:/usr/bin:/bin",
			expectFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, _ := DetectLFIFromResponse(tt.body)
			if found != tt.expectFound {
				t.Errorf("DetectLFIFromResponse() found = %v, want %v", found, tt.expectFound)
			}
		})
	}
}

func TestDetectLFIFromResponse_PHPSource(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		expectFound bool
	}{
		{
			name:        "PHP opening tag",
			body:        "<?php echo 'hello'; ?>",
			expectFound: true,
		},
		{
			name:        "base64 encoded PHP",
			body:        "PD9waHAgZWNobyAnaGVsbG8nOyA/Pg==",
			expectFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, _ := DetectLFIFromResponse(tt.body)
			if found != tt.expectFound {
				t.Errorf("DetectLFIFromResponse() found = %v, want %v", found, tt.expectFound)
			}
		})
	}
}

func TestLFIResult_Fields(t *testing.T) {
	result := LFIResult{
		Vulnerabilities: []LFIVulnerability{
			{
				URL:          "http://example.com/?file=../../../etc/passwd",
				Parameter:    "file",
				Payload:      "../../../etc/passwd",
				Evidence:     "/etc/passwd content",
				Severity:     "high",
				FileIncluded: "/etc/passwd",
			},
		},
		TestedParams:   10,
		TestedPayloads: 25,
	}

	if len(result.Vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(result.Vulnerabilities))
	}
	if result.Vulnerabilities[0].Parameter != "file" {
		t.Errorf("expected parameter 'file', got '%s'", result.Vulnerabilities[0].Parameter)
	}
	if result.Vulnerabilities[0].Severity != "high" {
		t.Errorf("expected severity 'high', got '%s'", result.Vulnerabilities[0].Severity)
	}
	if result.TestedParams != 10 {
		t.Errorf("expected 10 tested params, got %d", result.TestedParams)
	}
}

func TestLFIVulnerability_Fields(t *testing.T) {
	vuln := LFIVulnerability{
		URL:          "http://example.com/?page=../../../etc/passwd",
		Parameter:    "page",
		Payload:      "../../../etc/passwd",
		Evidence:     "/etc/passwd content",
		Severity:     "high",
		FileIncluded: "/etc/passwd",
	}

	if vuln.URL != "http://example.com/?page=../../../etc/passwd" {
		t.Errorf("unexpected URL: %s", vuln.URL)
	}
	if vuln.Parameter != "page" {
		t.Errorf("expected parameter 'page', got '%s'", vuln.Parameter)
	}
	if vuln.Payload != "../../../etc/passwd" {
		t.Errorf("unexpected payload: %s", vuln.Payload)
	}
	if vuln.Evidence != "/etc/passwd content" {
		t.Errorf("unexpected evidence: %s", vuln.Evidence)
	}
	if vuln.Severity != "high" {
		t.Errorf("expected severity 'high', got '%s'", vuln.Severity)
	}
}

func TestLFIPayloads_Exist(t *testing.T) {
	if len(lfiPayloads) == 0 {
		t.Error("lfiPayloads should not be empty")
	}

	// check that all payloads have required fields
	for i, payload := range lfiPayloads {
		if payload.payload == "" {
			t.Errorf("payload %d has empty payload", i)
		}
		if payload.target == "" {
			t.Errorf("payload %d has empty target", i)
		}
		if payload.severity == "" {
			t.Errorf("payload %d has empty severity", i)
		}
		if payload.severity != "critical" && payload.severity != "high" && payload.severity != "medium" && payload.severity != "low" {
			t.Errorf("payload %d has invalid severity: %s", i, payload.severity)
		}
	}
}

func TestCommonLFIParams_Exist(t *testing.T) {
	if len(commonLFIParams) == 0 {
		t.Error("commonLFIParams should not be empty")
	}

	expectedParams := []string{"file", "page", "path", "include"}
	for _, expected := range expectedParams {
		found := false
		for _, param := range commonLFIParams {
			if param == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected common param '%s' not found", expected)
		}
	}
}

func TestLFIEvidencePatterns_Exist(t *testing.T) {
	if len(lfiEvidencePatterns) == 0 {
		t.Error("lfiEvidencePatterns should not be empty")
	}

	// verify patterns compile and match expected content
	testCases := []struct {
		content     string
		shouldMatch bool
		description string
	}{
		{"root:x:0:0:root:/root:/bin/bash", true, "etc passwd root"},
		{"nobody:x:65534:65534:nobody", true, "etc passwd nobody"},
		{"[boot loader]", true, "boot.ini"},
		{"[operating systems]", true, "boot.ini"},
		{"127.0.0.1   localhost", true, "hosts file"},
		{"<html>Hello</html>", false, "normal html"},
	}

	for _, tc := range testCases {
		matched := false
		for _, pattern := range lfiEvidencePatterns {
			if pattern.pattern.MatchString(tc.content) {
				matched = true
				break
			}
		}
		if matched != tc.shouldMatch {
			t.Errorf("pattern match for %s: got %v, want %v", tc.description, matched, tc.shouldMatch)
		}
	}
}

func TestLFI_MockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if file == "../../../../../../../etc/passwd" || file == "/etc/passwd" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>Normal page</body></html>"))
		}
	}))
	defer server.Close()

	// verify server returns passwd content for LFI payload
	resp, err := http.Get(server.URL + "/?file=../../../../../../../etc/passwd")
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}
