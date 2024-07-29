package scan

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/dropalldatabases/sif/pkg/logger"
)

func Lfi(url string, logdir string) {
	fmt.Println(styles.Separator.Render("💭 Starting " + styles.Status.Render("LFI Scanning") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]
	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, " LFI scanning"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return
		}
	}

	whoislog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "LFI 💭",
	})

	whoislog.Infof("Starting LFI")

}
