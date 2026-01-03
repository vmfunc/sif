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

package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/dropalldatabases/sif/pkg/logger"
)

const shodanBaseURL = "https://api.shodan.io"

// ShodanResult represents the results from a Shodan host lookup
type ShodanResult struct {
	IP           string          `json:"ip_str"`
	Hostnames    []string        `json:"hostnames,omitempty"`
	Organization string          `json:"org,omitempty"`
	ASN          string          `json:"asn,omitempty"`
	ISP          string          `json:"isp,omitempty"`
	Country      string          `json:"country_name,omitempty"`
	City         string          `json:"city,omitempty"`
	OS           string          `json:"os,omitempty"`
	Ports        []int           `json:"ports,omitempty"`
	Vulns        []string        `json:"vulns,omitempty"`
	Services     []ShodanService `json:"services,omitempty"`
	LastUpdate   string          `json:"last_update,omitempty"`
}

// ShodanService represents a service found by Shodan
type ShodanService struct {
	Port     int    `json:"port"`
	Protocol string `json:"transport"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	Banner   string `json:"data,omitempty"`
	Module   string `json:"_shodan,omitempty"`
}

// shodanHostResponse is the raw response from Shodan API
type shodanHostResponse struct {
	IP          string       `json:"ip_str"`
	Hostnames   []string     `json:"hostnames"`
	Org         string       `json:"org"`
	ASN         string       `json:"asn"`
	ISP         string       `json:"isp"`
	CountryName string       `json:"country_name"`
	City        string       `json:"city"`
	OS          string       `json:"os"`
	Ports       []int        `json:"ports"`
	Vulns       []string     `json:"vulns"`
	Data        []shodanData `json:"data"`
	LastUpdate  string       `json:"last_update"`
}

// shodanMetadata represents the _shodan field in Shodan API responses.
// This provides type safety instead of using map[string]interface{}.
type shodanMetadata struct {
	Module  string `json:"module"`
	Crawler string `json:"crawler,omitempty"`
	ID      string `json:"id,omitempty"`
	Ptr     bool   `json:"ptr,omitempty"`
}

type shodanData struct {
	Port      int            `json:"port"`
	Transport string         `json:"transport"`
	Product   string         `json:"product"`
	Version   string         `json:"version"`
	Data      string         `json:"data"`
	Shodan    shodanMetadata `json:"_shodan"`
}

// Shodan performs a Shodan lookup for the given URL
// The API key should be provided via the SHODAN_API_KEY environment variable
func Shodan(targetURL string, timeout time.Duration, logdir string) (*ShodanResult, error) {
	fmt.Println(styles.Separator.Render("🔍 Starting " + styles.Status.Render("Shodan lookup") + "..."))

	shodanlog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Shodan 🔍",
	}).With("url", targetURL)

	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		shodanlog.Warn("SHODAN_API_KEY environment variable not set, skipping Shodan lookup")
		return nil, fmt.Errorf("SHODAN_API_KEY environment variable not set")
	}

	// extract hostname from URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}
	hostname := parsedURL.Hostname()

	// resolve hostname to IP
	ip, err := resolveHostname(hostname)
	if err != nil {
		shodanlog.Warnf("Failed to resolve hostname %s: %v", hostname, err)
		return nil, fmt.Errorf("failed to resolve hostname: %w", err)
	}

	shodanlog.Infof("Resolved %s to %s", hostname, ip)

	// query Shodan API
	result, err := queryShodanHost(ip, apiKey, timeout)
	if err != nil {
		shodanlog.Warnf("Shodan lookup failed: %v", err)
		return nil, err
	}

	// log results
	if logdir != "" {
		sanitizedURL := strings.Split(targetURL, "://")[1]
		if err := logger.WriteHeader(sanitizedURL, logdir, "Shodan lookup"); err != nil {
			shodanlog.Errorf("Error writing log header: %v", err)
		}
		logShodanResults(sanitizedURL, logdir, result)
	}

	// print results
	printShodanResults(shodanlog, result)

	return result, nil
}

func resolveHostname(hostname string) (string, error) {
	// check if already an IP
	if net.ParseIP(hostname) != nil {
		return hostname, nil
	}

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", err
	}

	// prefer IPv4
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}

	if len(ips) > 0 {
		return ips[0].String(), nil
	}

	return "", fmt.Errorf("no IP addresses found for %s", hostname)
}

func queryShodanHost(ip string, apiKey string, timeout time.Duration) (*ShodanResult, error) {
	client := &http.Client{Timeout: timeout}

	reqURL := fmt.Sprintf("%s/shodan/host/%s?key=%s", shodanBaseURL, ip, apiKey)
	resp, err := client.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("failed to query Shodan: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid Shodan API key")
	}

	if resp.StatusCode == http.StatusNotFound {
		return &ShodanResult{
			IP: ip,
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Shodan API error (status %d): %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var shodanResp shodanHostResponse
	if err := json.Unmarshal(body, &shodanResp); err != nil {
		return nil, fmt.Errorf("failed to parse Shodan response: %w", err)
	}

	// convert to our result type
	result := &ShodanResult{
		IP:           shodanResp.IP,
		Hostnames:    shodanResp.Hostnames,
		Organization: shodanResp.Org,
		ASN:          shodanResp.ASN,
		ISP:          shodanResp.ISP,
		Country:      shodanResp.CountryName,
		City:         shodanResp.City,
		OS:           shodanResp.OS,
		Ports:        shodanResp.Ports,
		Vulns:        shodanResp.Vulns,
		LastUpdate:   shodanResp.LastUpdate,
		Services:     make([]ShodanService, 0, len(shodanResp.Data)),
	}

	for _, data := range shodanResp.Data {
		service := ShodanService{
			Port:     data.Port,
			Protocol: data.Transport,
			Product:  data.Product,
			Version:  data.Version,
			Banner:   truncateBanner(data.Data, 200),
			Module:   data.Shodan.Module,
		}
		result.Services = append(result.Services, service)
	}

	return result, nil
}

func truncateBanner(banner string, maxLen int) string {
	banner = strings.TrimSpace(banner)
	banner = strings.ReplaceAll(banner, "\r\n", " ")
	banner = strings.ReplaceAll(banner, "\n", " ")

	if len(banner) > maxLen {
		return banner[:maxLen] + "..."
	}
	return banner
}

func printShodanResults(shodanlog *log.Logger, result *ShodanResult) {
	if result.IP != "" {
		shodanlog.Infof("IP: %s", styles.Highlight.Render(result.IP))
	}

	if len(result.Hostnames) > 0 {
		shodanlog.Infof("Hostnames: %s", strings.Join(result.Hostnames, ", "))
	}

	if result.Organization != "" {
		shodanlog.Infof("Organization: %s", result.Organization)
	}

	if result.ISP != "" {
		shodanlog.Infof("ISP: %s", result.ISP)
	}

	if result.Country != "" {
		location := result.Country
		if result.City != "" {
			location = result.City + ", " + result.Country
		}
		shodanlog.Infof("Location: %s", location)
	}

	if result.OS != "" {
		shodanlog.Infof("OS: %s", result.OS)
	}

	if len(result.Ports) > 0 {
		portStrs := make([]string, len(result.Ports))
		for i, port := range result.Ports {
			portStrs[i] = fmt.Sprintf("%d", port)
		}
		shodanlog.Infof("Open Ports: %s", styles.Status.Render(strings.Join(portStrs, ", ")))
	}

	if len(result.Vulns) > 0 {
		shodanlog.Warnf("Vulnerabilities: %s", styles.SeverityHigh.Render(strings.Join(result.Vulns, ", ")))
	}

	for _, service := range result.Services {
		serviceInfo := fmt.Sprintf("%d/%s", service.Port, service.Protocol)
		if service.Product != "" {
			serviceInfo += " - " + service.Product
			if service.Version != "" {
				serviceInfo += " " + service.Version
			}
		}
		shodanlog.Infof("Service: %s", serviceInfo)
		if service.Banner != "" {
			shodanlog.Debugf("  Banner: %s", service.Banner)
		}
	}
}

func logShodanResults(sanitizedURL string, logdir string, result *ShodanResult) {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("IP: %s\n", result.IP))

	if len(result.Hostnames) > 0 {
		sb.WriteString(fmt.Sprintf("Hostnames: %s\n", strings.Join(result.Hostnames, ", ")))
	}

	if result.Organization != "" {
		sb.WriteString(fmt.Sprintf("Organization: %s\n", result.Organization))
	}

	if result.ISP != "" {
		sb.WriteString(fmt.Sprintf("ISP: %s\n", result.ISP))
	}

	if result.Country != "" {
		location := result.Country
		if result.City != "" {
			location = result.City + ", " + result.Country
		}
		sb.WriteString(fmt.Sprintf("Location: %s\n", location))
	}

	if result.OS != "" {
		sb.WriteString(fmt.Sprintf("OS: %s\n", result.OS))
	}

	if len(result.Ports) > 0 {
		portStrs := make([]string, len(result.Ports))
		for i, port := range result.Ports {
			portStrs[i] = fmt.Sprintf("%d", port)
		}
		sb.WriteString(fmt.Sprintf("Open Ports: %s\n", strings.Join(portStrs, ", ")))
	}

	if len(result.Vulns) > 0 {
		sb.WriteString(fmt.Sprintf("Vulnerabilities: %s\n", strings.Join(result.Vulns, ", ")))
	}

	for _, service := range result.Services {
		serviceInfo := fmt.Sprintf("%d/%s", service.Port, service.Protocol)
		if service.Product != "" {
			serviceInfo += " - " + service.Product
			if service.Version != "" {
				serviceInfo += " " + service.Version
			}
		}
		sb.WriteString(fmt.Sprintf("Service: %s\n", serviceInfo))
	}

	logger.Write(sanitizedURL, logdir, sb.String())
}
