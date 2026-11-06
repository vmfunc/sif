# the sif tui

sif ships an interactive terminal ui built on [bubbletea](https://github.com/charmbracelet/bubbletea):

1. an interactive **picker** to choose what to scan
2. a live **dashboard** that streams findings as the scan runs, ending on a **summary**

<!-- asciinema/gif placeholder: docs/assets/tui.gif -->

## the picker

type a target with no scan flags and sif drops you into a menu instead of making you memorize the flag set:

```bash
sif https://example.com
```

the picker is a grouped, collapsible checklist of scans — Recon, Web vulns, Info/panels, Intel — each row showing its flag and a one-line description, so it teaches the CLI as you use it. a live "equivalent command" line at the bottom updates as you toggle, so you can graduate to flags.

### when it opens

the picker opens for `sif <url>` or `sif -u <url>` when **no scan flags** are set and stdin/stdout are both interactive terminals. it stays out of the way otherwise:

- any scan flag present → runs directly (pipelines and muscle memory keep working)
- `-silent`, `-api`, or piped stdin/stdout → never opens
- `-i` / `-pick` → force it open even when scan flags are set
- `-no-tui` → never open it

your last selection is saved to `<user-config>/sif/tui.yaml` and restored next launch.

### picker keys

| key | action |
| --- | --- |
| `j` / `k` / `↑` / `↓` | move |
| `space` | toggle the scan (on a sized scan, cycle off → small → medium → large) |
| `←` / `→` | step a sized scan's level |
| `a` | select/clear every scan in the focused group |
| `tab` | collapse/expand the focused group |
| `p` | cycle presets (quick, recon, web, full, passive) |
| `/` | filter the list |
| `c` | copy the equivalent command |
| `enter` / `r` | run the selected scans |
| `?` | toggle help |
| `q` / `ctrl+c` | cancel without scanning |

### presets

`p` cycles bundles that map to the common flag combos:

| preset | scans |
| --- | --- |
| quick | `-headers -framework` |
| recon | `-dnslist small -ports common -crawl -passive` |
| web | `-cors -xss -redirect -sql -lfi` |
| full | `-dirlist small -dnslist small -ports common -headers -sh -cms -framework -git -whois` |
| passive | `-passive` |

## the dashboard

### when it opens

the dashboard is the default view for any scan on an interactive terminal — after the picker, or straight away when scan flags are given. it only opens when stdin and stdout are both terminals with a usable size (and `TERM` isn't `dumb`); otherwise sif falls back to its normal streaming output:

- `-silent`, `-api`, or piped stdin/stdout → plain output
- `-no-tui` → plain output (also skips the picker)

while the dashboard is up, sif's console chrome is suppressed (the dashboard shows the same findings); warnings and errors are buffered and printed when it closes. after you quit, the usual run steps — notify, `-sarif`/`-markdown`/`-json` reports and the run summary — happen on the normal screen. quitting mid-scan aborts the run without writing partial reports.

the dashboard is a pure consumer of sif's scan event stream (`internal/event`). the scan engine runs in a background goroutine and emits events — target started, scanner started, each finding, scanner done, target done, run done — which the dashboard renders live. the engine does not know the tui exists; the tui is just one `event.Sink` among the console and report writers. quitting the dashboard before the scan finishes cancels it.

## dashboard layout

```
 sif v1.2.3 · 2/3 targets · 14 findings · 9 scanners · scanning
 ┌ targets ───────────┐ ┌ findings ─────────────────────────────┐
 ▸ ✓ https://a.com [7] │ ▸ [high] https://a.com · cors · permiss… │
   ⠋ https://b.com [4] │   [medium] https://a.com · headers · …   │
   · https://c.com  ·  │   [info] https://b.com · sh · …          │
 └────────────────────┘ └─────────────────────────────────────────┘
 floor:high  follow                                    (help line)
```

- **header** — version, how many targets are done, running finding and scanner totals, and whether the run is still scanning or done.
- **left pane** — one row per target: a spinner while scanning (`✓` when done), the target, and a finding-count badge colored by its highest severity.
- **right pane** — findings as they arrive, one per line, severity-colored, `[sev] target · module · title`.
- **footer** — the active severity floor / follow / filter state, then the help line.

## keybindings

| key | action |
| --- | --- |
| `j` / `↓` | move down |
| `k` / `↑` | move up (scrolling the findings pane up pauses follow) |
| `tab` | switch focus between the target and findings panes |
| `/` | filter findings by title, module or target (type, `enter` to commit, `esc` to clear) |
| `s` | cycle the severity floor: all → medium+ → high+ → critical+ → all |
| `f` | toggle showing only targets with findings |
| `p` | toggle follow mode (auto-scroll to newest); re-enabling snaps to the bottom |
| `g` / `G` | jump to the top / bottom of the findings |
| `enter` | expand the selected finding (target, module, evidence) |
| `c` | copy the selected finding's url |
| `w` | write a json report of every finding so far (to the `-json` path if given, else `sif-report-<timestamp>.json` in the current directory) |
| `?` | toggle the full help |
| `q` / `ctrl+c` | quit (cancels the scan) |

follow mode is on by default and auto-pauses the moment you scroll up, so a fast scan never yanks the view out from under you; `p` resumes and snaps back to the newest finding.

## summary

when the run finishes the dashboard switches to a summary: total findings, a per-severity breakdown, the scanners that ran, and every finding listed worst-first. it does **not** auto-exit.

| key | action |
| --- | --- |
| `j` / `k` / `↑` / `↓` | move through the findings |
| `g` / `G` | jump to the first / last finding |
| `enter` | open the selected finding's detail (target, module, evidence); `enter` again closes it |
| `s` | cycle the severity floor |
| `/` | filter by title, module or target |
| `w` | write a json report |
| `q` | quit |

## color

everything is themed through `internal/styles`/`internal/output` and respects `NO_COLOR` and the terminal's color profile, so the dashboard degrades to plain text in a pipe or a color-free terminal. finding text is sanitized of terminal control bytes before rendering.
