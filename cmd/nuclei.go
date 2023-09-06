package cmd

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/charmbracelet/log"
	"gopkg.in/yaml.v3"
)

const (
	nucleiURL  = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/v9.6.2/"
	nucleiFile = "templates-checksum.txt"
)

// only process attributes that can be used, with little to no metadata.
// there is no need to run any enum matching, because we trust nuclei-templates to have the proper
// value types, and we take the templates straight from their repository.
type Template struct {
	ID   string
	Info struct {
		Severity string
	}
	HTTP []struct {
		Path                          []string
		Raw                           []string
		Attack                        string
		Method                        string
		Body                          string
		Payloads                      map[string]interface{}
		Headers                       map[string]string
		RaceCount                     int
		MaxRedirects                  int
		PipelineCurrentConnections    int
		PipelineRequestsPerConnection int
		Threads                       int
		MaxSize                       int
		Fuzzing                       []string
		CookieReuse                   bool
		ReadAll                       bool
		Redirects                     bool
		HostRedirects                 bool
		Pipeline                      bool
		Unsafe                        bool
		Race                          bool
		ReqCondition                  bool
		StopAtFirstMatch              bool
		SkipVariablesCheck            bool
		IterateAll                    bool
		DigestUsername                string
		DigestPassword                string
		DisablePathAutomerge          bool
	}
	DNS []struct {
		Type              string
		Retries           int
		Trace             bool
		TraceMaxRecursion int
		Attack            string
		Payloads          map[string]interface{}
		Recursion         bool
		Resolvers         []string
	}
	File []struct {
		Extensions  []string
		DenyList    []string
		MaxSize     string
		Archive     bool
		MIMEType    bool
		NoRecursive bool
	}
	TCP []struct {
		Host     []string
		Attack   string
		Payloads map[string]interface{}
		Inputs   []struct {
			Data string
			Type string
			Read int
		}
		ReadSize int
		ReadAll  bool
	}
	Headless []struct {
		Attack   string
		Payloads map[string]interface{}
		Steps    []struct {
			Args   map[string]string
			Action string
		}
		UserAgent        string
		CustomUserAgent  string
		StopAtFirstMatch bool
		Fuzzing          []struct {
			Type      string
			Part      string
			Mode      string
			Keys      []string
			KeysRegex []string
			Values    []string
			Fuzz      []string
		}
		CookieReuse bool
	}
	SSL []struct {
		Address      string
		MinVersion   string
		MaxVersion   string
		CipherSuites []string
		ScanMode     string
	}
	Websocket []struct {
		Address string
		Inputs  []struct {
			Data string
		}
		Headers  map[string]string
		Attack   string
		Payloads map[string]interface{}
	}
	Whois []struct {
		Query  string
		Server string
	}
	SelfContained    bool
	StopAtFirstMatch bool
	Signature        string
	Variables        map[string]string
	Constants        map[string]interface{}
}

func Nuclei(url string, threads int, logdir string) {
	fmt.Println(separator.Render("⚛️ Starting " + statusstyle.Render("nuclei template scanning") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]

	if logdir != "" {
		f, err := os.OpenFile(logdir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Errorf("Error creating log file: %s", err)
			return
		}
		defer f.Close()
		f.WriteString(fmt.Sprintf("\n\n--------------\nStarting nuclei template scanning...\n--------------\n"))
	}

	logger := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "nuclei ⚛️",
	})
	nucleilog := logger.With("url", url)

	// We don't set timeout because it is specified by nuclei templates.
	// This &http.Client is only used for fetching the templates themselves from GitHub.
	client := &http.Client{}

	resp, err := client.Get(nucleiURL + nucleiFile)
	if err != nil {
		log.Errorf("Error downloading nuclei template list: %v", err)
		return
	}
	defer resp.Body.Close()
	var templateFiles []string
	scanner := bufio.NewScanner(resp.Body)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		templateFiles = append(templateFiles, scanner.Text())
	}

	var wg sync.WaitGroup
	wg.Add(threads)
	for thread := 0; thread < threads; thread++ {
		go func(thread int) {
			defer wg.Done()

			for i, templateFile := range templateFiles {
				if i%threads != thread {
					continue
				}

				if !strings.Contains(templateFile, ".yaml:") {
					continue
				}

				templateFile = strings.Split(templateFile, ":")[0]
				resp, err := client.Get(nucleiURL + templateFile)
				if err != nil {
					nucleilog.Errorf("Error downloading nuclei template: %v", err)
					continue
				}
				defer resp.Body.Close()
				data, _ := io.ReadAll(resp.Body)

				template := Template{}
				err = yaml.Unmarshal(data, &template)
				if err != nil {
					nucleilog.Errorf("Error reading nuclei template: %v", err)
					nucleilog.Errorf(string(data))
					continue
				}

				if template.Info.Severity == "undefined" || template.Info.Severity == "info" || template.Info.Severity == "unknown" {
					continue
				}

				log.Info(template.ID)
			}
		}(thread)
	}
	wg.Wait()
}
