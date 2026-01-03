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
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	charmlog "github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/logger"
	"github.com/dropalldatabases/sif/internal/output"
)

const commonPorts = "https://raw.githubusercontent.com/dropalldatabases/sif-runtime/main/ports/top-ports.txt"

func Ports(scope string, url string, timeout time.Duration, threads int, logdir string) ([]string, error) {
	log := output.Module("PORTS")
	log.Start()

	sanitizedURL := strings.Split(url, "://")[1]
	if logdir != "" {
		if err := logger.WriteHeader(sanitizedURL, logdir, scope+" port scanning"); err != nil {
			log.Error("Error creating log file: %v", err)
			return nil, err
		}
	}

	var ports []int
	switch scope {
	case "common":
		resp, err := http.Get(commonPorts)
		if err != nil {
			log.Error("Error downloading ports list: %s", err)
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

	progress := output.NewProgress(len(ports), "scanning")

	var openPorts []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(threads)

	for thread := 0; thread < threads; thread++ {
		go func(thread int) {
			defer wg.Done()

			for i, port := range ports {
				if i%threads != thread {
					continue
				}

				progress.Increment(strconv.Itoa(port))

				charmlog.Debugf("Looking up: %d", port)
				tcp, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", sanitizedURL, port), timeout)
				if err != nil {
					charmlog.Debugf("Error %d: %v", port, err)
				} else {
					progress.Pause()
					log.Success("open: %s:%s [tcp]", sanitizedURL, output.Highlight.Render(strconv.Itoa(port)))
					progress.Resume()

					mu.Lock()
					openPorts = append(openPorts, strconv.Itoa(port))
					mu.Unlock()
					tcp.Close()
				}
			}
		}(thread)
	}
	wg.Wait()
	progress.Done()

	log.Complete(len(openPorts), "open")

	return openPorts, nil
}
