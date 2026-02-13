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

package templates

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/charmbracelet/log"
)

const (
	archive = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v%s.tar.gz"
	ref     = "9.6.2"
)

func Install(logger *log.Logger) error {
	// Check if already exists
	if _, err := os.Stat("nuclei-templates"); err == nil {
		return nil
	}

	logger.Infof("nuclei-templates directory not found. Installing...")

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf(archive, ref), http.NoBody)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	tarball, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer tarball.Close()

	data := tar.NewReader(tarball)

	for {
		header, err := data.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(header.Name, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			file, err := os.Create(header.Name)
			if err != nil {
				return err
			}
			if _, err := io.Copy(file, data); err != nil {
				return err
			}
			file.Close()
		}
	}

	if err := os.Rename(fmt.Sprintf("nuclei-templates-%s", ref), "nuclei-templates"); err != nil {
		return err
	}

	return nil
}
