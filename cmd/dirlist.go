package cmd

import (
	"bufio"
	"net/http"
	"os"
	"strconv"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
)

const (
	directoryURL = "https://raw.githubusercontent.com/pushfs/sif-runtime/main/dirlist/"
	smallFile    = "directory-list-2.3-small.txt"
	mediumFile   = "directory-list-2.3-medium.txt"
	bigFile      = "directory-list-2.3-big.txt"
)

var statusstyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("#00ff1a"))

var directorystyle = lipgloss.NewStyle().
	Bold(true).
	Underline(true)

func Dirlist(size string, url string) {

	logger := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "Dirlist 📂",
	})
	dirlog := logger.With("url", url)

	var list string

	switch size {
	case "small":
		list = directoryURL + smallFile
	case "medium":
		list = directoryURL + mediumFile
	case "large":
		list = directoryURL + bigFile
	}

	dirlog.Infof("Starting %s directory listing", size)

	resp, err := http.Get(list)
	if err != nil {
		log.Errorf("Error downloading directory list: %s", err)
		return
	}
	var directories []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		directories = append(directories, scanner.Text())
	}

	for _, directory := range directories {
		log.Debugf("%s", directory)
		resp, err := http.Get(url + "/" + directory)
		if err != nil {
			log.Debugf("Error %s: %s", directory, err)
			return
		}

		if resp.StatusCode != 404 {
			// log url, directory, and status code\
			dirlog.Infof("%s [%s]", statusstyle.Render(strconv.Itoa(resp.StatusCode)), directorystyle.Render(directory))
		}
	}
}
