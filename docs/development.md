# development

setting up a development environment for sif.

## prerequisites

- go 1.26 or later
- git
- make

## clone and build

```bash
git clone https://github.com/vmfunc/sif.git
cd sif
make
```

## project structure

```
sif/
├── cmd/sif/          # entry point
│   └── main.go
├── sif.go            # main application logic
├── internal/         # private packages
│   ├── config/       # configuration parsing
│   ├── event/        # scan event stream (sinks consume findings live)
│   ├── logger/       # logging utilities
│   ├── modules/      # module system
│   ├── scan/         # built-in scans
│   └── styles/       # terminal styling
├── modules/          # built-in yaml modules
│   ├── http/         # http-based modules
│   ├── info/         # information gathering
│   └── recon/        # reconnaissance modules
├── docs/             # documentation
└── assets/           # images, etc
```

## running locally

```bash
# build
make

# run
./sif -u https://example.com

# run with debug
./sif -u https://example.com -d
```

## code quality

### format

```bash
gofmt -w .
```

### lint

ci pins golangci-lint v2.11.4 (`.github/workflows/go.yml`); other versions
report spurious issues against the v2 config, so pin it locally too:

```bash
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4 run
```

### test

```bash
go test ./...
```

### race detection

```bash
go test -race ./...
```

## adding a new scan

1. create a new file in `internal/scan/`
2. implement the scan function
3. add flag to `internal/config/config.go`
4. integrate in `sif.go`

see existing scans for examples.

## adding a new module

create a yaml file in `modules/`:

```yaml
id: my-new-module
info:
  name: my new security check
  author: your-name
  severity: medium
  description: what this checks for
  tags: [custom, security]

type: http

http:
  method: GET
  paths:
    - "{{BaseURL}}/path"

  matchers:
    - type: status
      status:
        - 200
```

see [modules.md](modules.md) for the full format.

## module system internals

the module system is in `internal/modules/`:

- `module.go` - core interface and types
- `registry.go` - module registration
- `loader.go` - discovery and loading
- `yaml.go` - yaml parsing
- `executor.go` - http execution

### adding a new module type

1. add type constant to `module.go`
2. implement executor in new file
3. update loader to handle new extension/type

## event stream

a run emits a stream of typed events as it scans, defined in `internal/event`.
`scanTarget` (in `sif.go`) emits, through `App.sink`, one `TargetStarted`, then
per scanner a `ScannerStarted` / one `FindingFound` per normalized finding /
`ScannerDone`, then `TargetDone`; the run ends with a single `RunDone` carrying
a `Summary`. findings on the stream are flattened through the same
`finding.Flatten` path the batch consumers use, so a live consumer sees exactly
what the report/notify output reports.

anything that wants to watch a run live implements `event.Sink` (a single
`Emit(event.Event)` method) and is attached to the run's `event.Multiplexer`.
the built-in `event.Collector` sink aggregates findings and scanner labels for
the run summary; the live TUI is simply a second sink. the scanners themselves
stay unaware of the stream — only `scanTarget` emits.

`internal/event` lives outside `internal/scan` on purpose: `internal/finding`
imports `internal/scan` (`finding.Flatten` type-switches on scan result types),
so `internal/scan` cannot import `finding`. the event stream carries
`finding.Finding` values, so it sits one level up.

## testing

### unit tests

```bash
go test ./internal/...
```

### integration tests

run the scanners against a local testbed that plants the artifacts each one
should find (network-free, behind a build tag):

```bash
go test -tags=integration ./internal/scan/...
```

### functional test

```bash
./sif -u https://example.com -am
```

### test modules

```bash
./sif -lm  # list modules
./sif -u https://example.com -m my-module -d  # test specific module
```

## pull requests

1. fork the repository
2. create a feature branch
3. make changes
4. run `gofmt -w .` and `golangci-lint run` (pinned version, see [lint](#lint))
5. submit pr

### commit messages

use lowercase, present tense:

```
add sql injection module
fix timeout handling in http executor
update readme with new flags
```

## release process

releases are automated via github actions on push to main.

binaries are built for:
- linux (amd64, 386, arm64)
- macos (amd64, arm64)
- windows (amd64, 386)

## resources

- [go documentation](https://golang.org/doc/)
- [goflags](https://github.com/projectdiscovery/goflags) - cli parsing
- [nuclei templates](https://github.com/projectdiscovery/nuclei-templates) - module format inspiration
