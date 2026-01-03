# development

setting up a development environment for sif.

## prerequisites

- go 1.23 or later
- git
- make

## clone and build

```bash
git clone https://github.com/dropalldatabases/sif.git
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
│   ├── logger/       # logging utilities
│   ├── modules/      # module system
│   ├── scan/         # built-in scans
│   ├── styles/       # terminal styling
│   └── worker/       # worker pool
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

```bash
golangci-lint run
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

## testing

### unit tests

```bash
go test ./internal/...
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
4. run `gofmt -w .` and `golangci-lint run`
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
