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
	"github.com/charmbracelet/log"
	"github.com/likexian/whois"
	"github.com/vmfunc/sif/internal/logger"
	"github.com/vmfunc/sif/internal/output"
)

func Whois(url string, logdir string) {
	output.ScanStart("WHOIS lookup")

	sanitizedURL := stripScheme(url)
	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, " WHOIS scanning"); err != nil {
			output.Error("Error creating log file: %v", err)
			return
		}
	}

	result, err := whois.Whois(sanitizedURL)
	if err == nil {
		log.Info(result)
		logger.Write(sanitizedURL, logdir, result)
		output.ScanComplete("WHOIS lookup", 1, "completed")
	} else {
		output.Error("WHOIS lookup failed: %v", err)
	}
}
