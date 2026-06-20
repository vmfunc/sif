# configuration

runtime configuration options for sif.

## environment variables

### SHODAN_API_KEY

required for shodan lookups.

```bash
export SHODAN_API_KEY=your-api-key-here
./sif -u https://example.com -shodan
```

## command line options

### timeout

default request timeout is 10 seconds.

```bash
# increase for slow targets
./sif -u https://example.com -t 30s

# decrease for fast scans
./sif -u https://example.com -t 5s
```

### threads

default is 10 concurrent threads.

```bash
# more threads for faster scanning
./sif -u https://example.com --threads 50

# fewer threads to reduce load
./sif -u https://example.com --threads 5
```

### logging

save output to files:

```bash
./sif -u https://example.com -l ./logs
```

creates timestamped log files in the specified directory.

### debug mode

enable verbose logging:

```bash
./sif -u https://example.com -d
```

## user modules

place custom modules in:

- linux/macos: `~/.config/sif/modules/`
- windows: `%LOCALAPPDATA%\sif\modules\`

### directory structure

```
~/.config/sif/
├── modules/
│   ├── http/
│   │   └── my-sqli-check.yaml
│   ├── recon/
│   │   └── custom-paths.yaml
│   └── my-module.yaml
```

modules can be organized in subdirectories or placed directly in the modules folder.

### overriding built-in modules

user modules with the same id as built-in modules will override them:

```yaml
# ~/.config/sif/modules/sqli-error-based.yaml
# this overrides the built-in sqli-error-based module

id: sqli-error-based
info:
  name: my custom sqli check
  # ...
```

## custom signatures

framework detection (`-framework`) also loads user-defined detectors from yaml
files, so a framework sif does not ship can be detected without rebuilding:

- linux/macos: `~/.config/sif/signatures/`
- windows: `%LOCALAPPDATA%\sif\signatures\`

each file defines one detector; place them directly in the directory, as
subdirectories are not scanned. `header: true` matches a response header name or
value (case-insensitive) instead of the body; the optional `version` block pulls
a version out of the body.

```yaml
# ~/.config/sif/signatures/ghost.yaml
name: Ghost
signatures:
  - pattern: 'content="Ghost'
    weight: 0.6
  - pattern: 'X-Ghost-Cache'
    weight: 0.4
    header: true
version:
  regex: 'content="Ghost ([0-9.]+)'
  group: 1
```

a detector reports a match once its matched signature weights sum past half, so
weight your signatures to total about `1.0`. a name matching a built-in detector
overrides it and inherits that built-in's version patterns and known cves, the
same as user modules.

## performance tuning

### fast scans

```bash
./sif -u https://example.com \
  --threads 50 \
  -t 5s \
  -dirlist small \
  -dnslist small
```

### thorough scans

```bash
./sif -u https://example.com \
  --threads 10 \
  -t 30s \
  -dirlist large \
  -dnslist large \
  -ports full
```

### low-impact scans

reduce load on target:

```bash
./sif -u https://example.com \
  --threads 2 \
  -t 10s
```

## output formats

### console (default)

human-readable output with colors and formatting.

### json (api mode)

```bash
./sif -u https://example.com -api
```

returns structured json:

```json
{
  "url": "https://example.com",
  "results": [
    {
      "id": "sqli-error-based",
      "data": {
        "findings": [...]
      }
    }
  ]
}
```

### log files

```bash
./sif -u https://example.com -l ./logs
```

creates separate log files for each scan type.
