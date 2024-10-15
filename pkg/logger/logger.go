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
