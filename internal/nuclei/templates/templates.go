/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2026 vmfunc, xyzeva,                                               :
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
	"path/filepath"
	"strings"

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
	defer func() {
		if cerr := tarball.Close(); cerr != nil {
			logger.Warnf("closing gzip reader: %v", cerr)
		}
	}()

	data := tar.NewReader(tarball)

	dest, err := os.Getwd()
	if err != nil {
		return err
	}
	cleanDest := filepath.Clean(dest)

	for {
		header, err := data.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		// guard against path traversal ("Zip Slip"): the resolved path must
		// stay within the extraction directory before any filesystem op.
		target := filepath.Join(cleanDest, header.Name)
		if !strings.HasPrefix(target, cleanDest+string(os.PathSeparator)) {
			return fmt.Errorf("invalid archive entry %q: escapes extraction directory", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(target, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			file, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(file, data); err != nil {
				file.Close()
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
