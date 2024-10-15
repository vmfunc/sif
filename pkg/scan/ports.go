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
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/dropalldatabases/sif/pkg/logger"
)

const commonPorts = "https://raw.githubusercontent.com/dropalldatabases/sif-runtime/main/ports/top-ports.txt"

func Ports(scope string, url string, timeout time.Duration, threads int, logdir string) ([]string, error) {
	log.Printf(styles.Separator.Render("🚪 Starting " + styles.Status.Render("port scanning") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]
	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, scope+" port scanning"); err != nil {
			log.Errorf("Error creating log file: %v", err)
			return nil, err
		}
	}

	portlog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Ports 🚪",
	})

	portlog.Infof("Starting %s port scanning", scope)

	var ports []int
	switch scope {
	case "common":
		resp, err := http.Get(commonPorts)
		if err != nil {
			log.Errorf("Error downloading ports list: %s", err)
			return nil, err
		}
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			if port, err := strconv.Atoi(scanner.Text()); err == nil {
				ports = append(ports, port)
			}
		}
	case "full":
		ports = make([]int, 65536)
		for i := range ports {
			ports[i] = i
		}
	}

	var openPorts []string
	var wg sync.WaitGroup
	wg.Add(threads)
	for thread := 0; thread < threads; thread++ {
		go func(thread int) {
			defer wg.Done()

			for i, port := range ports {
				if i%threads != thread {
					continue
				}

				log.Debugf("Looking up: %d", port)
				tcp, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", sanitizedURL, port), timeout)
				if err != nil {
					log.Debugf("Error %d: %v", port, err)
				} else {
					openPorts = append(openPorts, strconv.Itoa(port))
					portlog.Infof("%s %s:%s", styles.Status.Render("[tcp]"), sanitizedURL, styles.Highlight.Render(strconv.Itoa(port)))
					tcp.Close()
				}
			}
		}(thread)
	}
	wg.Wait()

	if len(openPorts) > 0 {
		portlog.Infof("Found %d open ports: %s", len(openPorts), strings.Join(openPorts, ", "))
	} else {
		portlog.Error("Found no open ports")
	}

	return openPorts, nil
}
