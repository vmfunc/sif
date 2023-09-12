package scan

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/dropalldatabases/sif/internal/nuclei/format"
	"github.com/dropalldatabases/sif/internal/nuclei/templates"
	"github.com/dropalldatabases/sif/internal/styles"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/ratelimit"
)

func Nuclei(url string, timeout time.Duration, threads int, logdir string) {
	fmt.Println(styles.Separator.Render("⚛️ Starting " + styles.Status.Render("nuclei template scanning") + "..."))

	sanitizedURL := strings.Split(url, "://")[1]

	nucleilog := log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "nuclei ⚛️",
	}).With("url", url)

	// Apply threads, timeout, log settings
	options := types.DefaultOptions()
	options.TemplateThreads = threads
	options.Timeout = int(timeout.Seconds())

	// Get templates
	templates.Install(nucleilog)
	pwd, _ := os.Getwd()
	config.DefaultConfig.SetTemplatesDir(pwd)
	catalog := disk.NewCatalog(pwd)

	// Custom output
	outputWriter := testutils.NewMockOutputWriter()
	outputWriter.WriteCallback = func(event *output.ResultEvent) {
		if event.Matched != "" {
			nucleilog.Infof(format.FormatLine(event))

			// TODO: metasploit
		}
	}

	cache := hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount, nil)
	defer cache.Close()

	progressClient := &testutils.MockProgressClient{}
	reportingClient, _ := reporting.New(&reporting.Options{}, "")
	defer reportingClient.Close()

	interactOpts := interactsh.DefaultOptions(outputWriter, reportingClient, progressClient)
	interactClient, err := interactsh.New(interactOpts)
	if err != nil {
		log.Fatalf("Could not create interact client: %s\n", err)
	}
	defer interactClient.Close()

	protocolstate.Init(options)
	protocolinit.Init(options)

	executorOpts := protocols.ExecutorOptions{
		Output:       outputWriter,
		Progress:     progressClient,
		Catalog:      catalog,
		Options:      options,
		IssuesClient: reportingClient,
		RateLimiter:  ratelimit.New(context.Background(), 150, time.Second),
		Interactsh:   interactClient,
		ResumeCfg:    types.NewResumeCfg(),
	}
	engine := core.New(options)
	engine.SetExecuterOptions(executorOpts)

	workflowLoader, err := parsers.NewLoader(&executorOpts)
	if err != nil {
		nucleilog.Fatalf("Could not create workflow loader: %s\n", err)
	}
	executorOpts.WorkflowLoader = workflowLoader

	store, err := loader.New(loader.NewConfig(options, catalog, executorOpts))
	if err != nil {
		nucleilog.Fatalf("Could not create loader client: %s\n", err)
	}
	store.Load()

	inputArgs := []*contextargs.MetaInput{{Input: sanitizedURL}}
	input := &inputs.SimpleInputProvider{Inputs: inputArgs}

	_ = engine.Execute(store.Templates(), input)
	engine.WorkPool().Wait()
}
