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

### templates

`-template` loads a batch of scan settings from a built-in preset or a local yaml file, so a run does not have to pass every flag. see the [usage guide](usage.md) for the presets and file format. command-line flags still take precedence over the template.

sif also reads an ambient config at `~/.config/sif/config.yaml` (created on first run) keyed by the same flag names. passing `-template` uses that template as the config for the run instead of the ambient file.

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
