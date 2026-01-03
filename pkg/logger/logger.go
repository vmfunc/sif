/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc, xyzeva,                                               :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package logger

import (
	"fmt"
	"os"
	"strings"
)

func Init(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err = os.Mkdir(dir, 0755); err != nil {
			return err
		}
	}

	return nil
}

func CreateFile(logFiles *[]string, url string, dir string) error {
	sanitizedURL := strings.Split(url, "://")[1]
	if _, err := os.Stat(dir + "/" + sanitizedURL + ".log"); os.IsNotExist(err) {
		f, err := os.OpenFile(dir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return err
		}

		defer f.Close()
	}

	f, err := os.OpenFile(dir+"/"+sanitizedURL+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	f.WriteString(fmt.Sprintf("       _____________\n__________(_)__  __/\n__  ___/_  /__  /_  \n_(__  )_  / _  __/  \n/____/ /_/  /_/    \n\nsif log file for %s\nhttps://sif.sh\n\n", url))
	*logFiles = append(*logFiles, dir+"/"+sanitizedURL+".log")

	return nil
}

func Write(url string, dir string, text string) error {
	f, err := os.OpenFile(dir+"/"+url+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	f.WriteString(text)

	return nil
}

func WriteHeader(url string, dir string, scan string) error {
	return Write(url, dir, fmt.Sprintf("\n\n--------------\nStarting %s\n--------------\n", scan))
}
