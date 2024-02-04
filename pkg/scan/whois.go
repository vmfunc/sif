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
		if err := logger.WriteHeader(sanitizedURL, logdir, " port scanning"); err != nil {
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
