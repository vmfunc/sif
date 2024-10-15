/*
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                                  SIF                                         ║
║                                                                              ║
║        Blazing-fast pentesting suite written in Go                           ║
║                                                                              ║
║        Copyright (c) 2023-2024 vmfunc, xyzeva, lunchcat contributors         ║
║                    and other sif contributors.                               ║
║                                                                              ║
║                                                                              ║
║        Use of this tool is restricted to research and educational            ║
║        purposes only. Usage in a production environment outside              ║
║        of these categories is strictly prohibited.                           ║
║                                                                              ║
║        Any person or entity wishing to use this tool outside of              ║
║        research or educational purposes must purchase a license              ║
║        from https://lunchcat.dev                                             ║
║                                                                              ║
║        For more information, visit: https://github.com/lunchcat/sif          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
*/

package scan

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/dropalldatabases/sif/pkg/logger"
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
