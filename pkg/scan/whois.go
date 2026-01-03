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
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/likexian/whois"
)

func Whois(url string, logdir string) {
	fmt.Println(styles.Separator.Render("💭 Starting " + styles.Status.Render("WHOIS Lookup") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]
	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, " WHOIS scanning"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return
		}
	}

	whoislog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "WHOIS 💭",
	})

	whoislog.Infof("Starting WHOIS")

	result, err := whois.Whois(sanitizedURL)
	if err == nil {
		log.Info(result)
		logger.Write(sanitizedURL, logdir, result)
	}
}
