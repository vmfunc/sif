/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (vmfunc), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package scan

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/nuclei/format"
	"github.com/dropalldatabases/sif/internal/nuclei/templates"
	sifoutput "github.com/dropalldatabases/sif/internal/output"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func Nuclei(url string, timeout time.Duration, threads int, logdir string) ([]output.ResultEvent, error) {
	sifoutput.ScanStart("nuclei template scanning")

	spin := sifoutput.NewSpinner("Running nuclei templates")
	spin.Start()

	nucleilog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "nuclei",
	}).With("url", url)

	templates.Install(nucleilog)
	pwd, err := os.Getwd()
	if err != nil {
		spin.Stop()
		return nil, err
	}

	ctx := context.Background()
	ne, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{pwd + "/nuclei-templates"},
		}),
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:           threads,
			HostConcurrency:               1,
			HeadlessHostConcurrency:       1,
			HeadlessTemplateConcurrency:   1,
			JavascriptTemplateConcurrency: 1,
			TemplatePayloadConcurrency:    25,
			ProbeConcurrency:              50,
		}),
		nuclei.WithNetworkConfig(nuclei.NetworkConfig{
			Timeout: int(timeout.Seconds()),
		}),
		nuclei.DisableUpdateCheck(),
	)
	if err != nil {
		spin.Stop()
		return nil, err
	}
	defer ne.Close()

	sanitizedURL := strings.Split(url, "://")[1]
	ne.LoadTargets([]string{sanitizedURL}, false)

	var results []output.ResultEvent
	var mu sync.Mutex

	err = ne.ExecuteCallbackWithCtx(ctx, func(event *output.ResultEvent) {
		if event.Matched != "" {
			nucleilog.Infof("%s", format.FormatLine(event))
			mu.Lock()
			results = append(results, *event)
			mu.Unlock()
		}
	})

	spin.Stop()
	sifoutput.ScanComplete("nuclei template scanning", len(results), "found")

	return results, err
}
