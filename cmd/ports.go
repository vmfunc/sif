package cmd

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/log"
)

const commonPorts = "https://raw.githubusercontent.com/pushfs/sif-runtime/main/ports/top-ports.txt"

func Ports(scope string, url string, timeout time.Duration, logdir string) {
	fmt.Println(separator.Render("🚪 Starting " + statusstyle.Render("port scanning") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]
	if logdir != "" {
		f, err := os.OpenFile(logdir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Errorf("Error creating log file: %s", err)
			return
		}
		defer f.Close()
		f.WriteString(fmt.Sprintf("\n\n--------------\nStarting %s port scanning\n--------------\n", scope))
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
			return
		}
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
	default:
		log.Errorf("Invalid ports scope %s. Please choose either common or full", portstyle.Render(scope))
		return
	}

	var openPorts []string
	for _, port := range ports {
		log.Debugf("Looking up: %d", port)
		tcp, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", sanitizedURL, port), timeout)
		if err != nil {
			log.Debugf("Error %d: %v", port, err)
		} else {
			openPorts = append(openPorts, strconv.Itoa(port))
			portlog.Infof("%s %s:%s", statusstyle.Render("[tcp]"), sanitizedURL, portstyle.Render(strconv.Itoa(port)))
			tcp.Close()
		}
	}

	if len(openPorts) > 0 {
		portlog.Infof("Found %d open ports: %s", len(openPorts), strings.Join(openPorts, ", "))
	} else {
		portlog.Error("Found no open ports")
	}
}
