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

// Package notify ships findings to chat/webhook sinks (slack, discord, telegram,
// generic webhook) so a continuous-recon run can alert on what it turns up. every
// provider is one POST through httpx.Client, so the global proxy/rate-limit/header
// config applies uniformly and there's no extra http stack to keep in sync.
package notify

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/vmfunc/sif/internal/finding"
	"github.com/vmfunc/sif/internal/httpx"
	"github.com/vmfunc/sif/internal/output"
)

// Options carries the runtime knobs Send needs. Timeout bounds each provider's
// POST; ConfigPath is an optional yaml file whose values override env. severity
// filtering is the caller's job - Send ships whatever batch it's handed.
type Options struct {
	Timeout    time.Duration
	ConfigPath string
}

// Send dispatches findings to every configured provider. config resolves
// env-first, then a yaml file overlays it (notify-compatible key names). a
// provider with no destination is skipped, so zero configured providers makes
// Send a silent no-op - notify is opt-in and never errors just for being unwired.
// an empty findings slice is also a no-op: nothing to report.
func Send(ctx context.Context, findings []finding.Finding, opts Options) error {
	if len(findings) == 0 {
		return nil
	}

	cfg, err := loadConfig(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("notify config: %w", err)
	}

	providers := cfg.providers()
	if len(providers) == 0 {
		// nothing wired up; opt-in feature stays quiet rather than erroring.
		return nil
	}

	log := output.Module("NOTIFY")
	client := httpx.Client(opts.Timeout)

	// run every provider; a failure on one sink must not suppress the others, so
	// errors accumulate and the first is returned after all have been attempted.
	var firstErr error
	for i := 0; i < len(providers); i++ {
		p := providers[i]
		if err := p.send(ctx, client, findings); err != nil {
			log.Error("%s delivery failed: %v", p.name(), err)
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", p.name(), err)
			}
			continue
		}
		log.Success("sent %d findings to %s", len(findings), p.name())
	}

	return firstErr
}

// provider is one delivery sink. name is for logging; send formats findings into
// the sink's payload and POSTs it through the shared client.
type provider interface {
	name() string
	send(ctx context.Context, client *http.Client, findings []finding.Finding) error
}
