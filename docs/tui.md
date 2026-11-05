# the sif tui

sif ships an interactive terminal ui built on [bubbletea](https://github.com/charmbracelet/bubbletea). it has two screens in one program:

1. an interactive **picker** to choose what to scan (coming in the next release)
2. a live **dashboard** that streams findings as the scan runs, ending on a **summary**

this page documents the dashboard and summary. the picker section lands with the `sif <url>` drop-into-picker flow.

<!-- asciinema/gif placeholder: docs/assets/tui.gif -->

## how it works

the dashboard is a pure consumer of sif's scan event stream (`internal/event`). the scan engine runs in a background goroutine and emits events — target started, scanner started, each finding, scanner done, target done, run done — which the dashboard renders live. the engine does not know the tui exists; the tui is just one `event.Sink` among the console and report writers. quitting the dashboard cancels the scan context (reports still flush on the way out).

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
| `w` | write a report now |
| `?` | toggle the full help |
| `q` / `ctrl+c` | quit (cancels the scan) |

follow mode is on by default and auto-pauses the moment you scroll up, so a fast scan never yanks the view out from under you; `p` resumes and snaps back to the newest finding.

## summary

when the run finishes the dashboard switches to a summary: total findings, a per-severity breakdown, and the scanners that ran. it does **not** auto-exit — press `w` to write a report or `q` to quit.

## color

everything is themed through `internal/styles`/`internal/output` and respects `NO_COLOR` and the terminal's color profile, so the dashboard degrades to plain text in a pipe or a color-free terminal. finding text is sanitized of terminal control bytes before rendering.
