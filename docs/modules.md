# writing sif modules

sif modules are yaml files that define security checks. they're similar to nuclei templates but designed specifically for sif.

## module locations

- **built-in**: `modules/` directory in the sif installation
- **user-defined**: `~/.config/sif/modules/` (linux/macos) or `%LOCALAPPDATA%\sif\modules\` (windows)

user modules can override built-in modules with the same id.

## basic structure

```yaml
id: unique-module-id
info:
  name: human readable name
  author: your-name
  severity: low|medium|high|critical|info
  description: what this module checks for
  tags: [tag1, tag2, tag3]

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

## fields

### id (required)

unique identifier for the module. use lowercase with hyphens.

```yaml
id: sqli-error-based
```

### info (required)

metadata about the module.

```yaml
info:
  name: SQL Injection Detection
  author: sif
  severity: high
  description: detects sql injection via error messages
  tags: [sqli, injection, owasp-top10]
```

**severity levels:**
- `info` - informational finding
- `low` - minor issue
- `medium` - moderate security concern
- `high` - serious vulnerability
- `critical` - critical security flaw

### type (required)

module type. `http` and `tcp` are supported.

```yaml
type: http
```

### http

http request configuration.

#### method

http method to use.

```yaml
http:
  method: GET
```

supported: `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`

#### paths

urls to check. use `{{BaseURL}}` as placeholder for the target.

```yaml
http:
  paths:
    - "{{BaseURL}}/.git/HEAD"
    - "{{BaseURL}}/.git/config"
    - "{{BaseURL}}/admin"
```

#### payloads

values to inject into paths. use `{{payload}}` as placeholder.

```yaml
http:
  paths:
    - "{{BaseURL}}/?id={{payload}}"

  payloads:
    - "'"
    - "1' OR '1'='1"
    - "1; DROP TABLE--"
```

each payload creates a separate request for each path.

#### attack

how paths and payloads combine into requests.

```yaml
http:
  attack: pitchfork
```

- `clusterbomb` (default) - every path is tried with every payload
- `pitchfork` - path and payload are paired by index, stopping at the shorter list

#### wordlist

a local file whose non-empty lines fuzz the `{{word}}` placeholder, one request
per word. paths without `{{word}}` are still requested as-is.

```yaml
http:
  wordlist: /usr/share/wordlists/dirs.txt
  paths:
    - "{{BaseURL}}/{{word}}"
```
#### headers

custom headers to send.

```yaml
http:
  headers:
    User-Agent: "Mozilla/5.0"
    X-Custom-Header: "value"
```

#### body

request body for POST/PUT requests.

```yaml
http:
  method: POST
  body: '{"username": "admin", "password": "{{payload}}"}'
```

#### threads

concurrent requests (default: 10).

```yaml
http:
  threads: 5
```

### tcp

raw tcp configuration. connects to a port, optionally sends a payload, and runs
matchers and extractors against the response banner.

#### port

the tcp port to connect to (required, 1-65535). the port selects the service, so
the target's own scheme and port are ignored.

```yaml
tcp:
  port: 6379
```

#### data

an optional payload sent after connecting. sif decodes C-style escapes in the
value, so `\r`, `\n`, `\t`, `\\` and `\xHH` reach the wire as the raw bytes no
matter how the yaml scalar is quoted; an unrecognized escape is left verbatim. a
server that only banners (ssh, smtp) needs no data at all.

```yaml
tcp:
  port: 6379
  data: "INFO\r\n"
```

#### matchers and extractors

tcp runs `word`, `regex` and `size` matchers (no `status`/`favicon`, those are
http only) against the banner string, and `regex` extractors pull values out of
it. there is no `part` selector: the banner is the only stream.

```yaml
tcp:
  port: 6379
  data: "INFO\r\n"
  matchers:
    - type: word
      words:
        - "redis_version:"
  extractors:
    - type: regex
      name: redis_version
      regex:
        - "redis_version:([0-9.]+)"
      group: 1
```

see `modules/recon/redis-unauth-exposure.yaml` for the full module.

## matchers

matchers determine if a response indicates a finding.

### status matcher

match http status codes.

```yaml
matchers:
  - type: status
    status:
      - 200
      - 301
      - 302
```

### word matcher

match words in response.

```yaml
matchers:
  - type: word
    part: body
    words:
      - "admin"
      - "login"
    condition: or
```

**parts:**
- `body` - response body
- `header` - response headers

**conditions:**
- `or` - match any word (default)
- `and` - match all words

### regex matcher

match regex patterns.

```yaml
matchers:
  - type: regex
    part: body
    regex:
      - "SQL syntax.*MySQL"
      - "ORA-[0-9]+"
      - "PostgreSQL.*ERROR"
    condition: or
```

### size matcher

match the response body length in bytes (measured after the 5 MB response cap, so larger sizes never match).

```yaml
matchers:
  - type: size
    size:
      - 0
      - 1337
```

### favicon matcher

match the shodan-style mmh3 hash of the response body. point the module at a
favicon and list the hashes of the tech you want to fingerprint.

```yaml
http:
  paths:
    - "{{BaseURL}}/favicon.ico"
  matchers:
    - type: status
      status:
        - 200
    - type: favicon
      hash:
        - -235701012   # jenkins
        - 1278322581   # grafana
```

the hash is shodan's `http.favicon.hash` value. paste it signed or unsigned;
both 32-bit forms are accepted, so values from shodan or any favicon-hash tool
drop in without conversion. pair it with a `status: 200` matcher so an error
page served for `/favicon.ico` is not hashed. a finding fires when the body
hashes to any listed value.
### combining matchers

multiple matchers are combined with AND logic by default.

```yaml
matchers:
  - type: status
    status:
      - 200

  - type: word
    part: body
    words:
      - "ref: refs/"
    condition: or
```

this matches responses with status 200 AND containing "ref: refs/".

set `matchers-condition: or` to fire when any matcher hits instead of all; it
applies to `http` and `tcp` modules alike.

```yaml
http:
  matchers-condition: or
  matchers:
    - type: status
      status:
        - 401

    - type: status
      status:
        - 403
```

this matches a 401 OR a 403 response. `matchers-condition` accepts `and` (the
default) or `or`; any other value fails at load.

## extractors

extractors pull data from responses.

### regex extractor

```yaml
extractors:
  - type: regex
    name: version
    part: body
    regex:
      - "version[\"']?\\s*[:=]\\s*[\"']?([0-9.]+)"
    group: 1
```

**group**: capture group to extract (0 = full match, 1+ = groups)

### kv extractor

record every response header as a key-value pair, namespaced by `name`.

```yaml
extractors:
  - type: kv
    name: headers
    part: header
```

### json extractor

extract values from a json body by gjson path (github.com/tidwall/gjson); the
first path that exists is stored under name.

```yaml
extractors:
  - type: json
    name: version
    part: body
    json:
      - "version"
      - "data.version"
```

## examples

### exposed git repository

```yaml
id: git-exposed
info:
  name: exposed git repository
  author: sif
  severity: high
  description: detects exposed .git directories
  tags: [git, exposure, source-code]

type: http

http:
  method: GET
  paths:
    - "{{BaseURL}}/.git/HEAD"
    - "{{BaseURL}}/.git/config"

  matchers:
    - type: word
      part: body
      words:
        - "ref: refs/"
        - "[core]"
      condition: or

    - type: status
      status:
        - 200

  extractors:
    - type: regex
      name: branch
      part: body
      regex:
        - "ref: refs/heads/(.+)"
      group: 1
```

### sql injection detection

```yaml
id: sqli-error-based
info:
  name: sql injection (error-based)
  author: sif
  severity: high
  description: detects sql injection via database errors
  tags: [sqli, injection, database]

type: http

http:
  method: GET
  paths:
    - "{{BaseURL}}/?id={{payload}}"
    - "{{BaseURL}}/search?q={{payload}}"

  payloads:
    - "'"
    - "1' OR '1'='1"
    - "1; SELECT * FROM--"

  threads: 10

  matchers:
    - type: regex
      part: body
      regex:
        - "SQL syntax.*MySQL"
        - "ORA-[0-9]+"
        - "PostgreSQL.*ERROR"
        - "Microsoft SQL Server"
      condition: or
```

### security headers check

```yaml
id: security-headers
info:
  name: security headers analysis
  author: sif
  severity: info
  description: checks for missing security headers
  tags: [headers, security, info]

type: http

http:
  method: GET
  paths:
    - "{{BaseURL}}/"

  matchers:
    - type: status
      status:
        - 200

  extractors:
    - type: kv
      name: headers
      part: header
```

## tips

1. **use specific paths** - don't just check `/`, be specific about what you're looking for

2. **combine matchers** - use status + content matchers together to reduce false positives

3. **limit payloads** - too many payloads slow down scans, pick the most effective ones

4. **tag properly** - use consistent tags so modules can be filtered with `-mt`

5. **test locally** - run your module against a test target before sharing

## running modules

```bash
# list all modules
./sif -lm

# run specific module
./sif -u https://example.com -m git-exposed

# run multiple modules
./sif -u https://example.com -m git-exposed,sqli-error-based

# run by tag
./sif -u https://example.com -mt owasp-top10

# run all modules
./sif -u https://example.com -am
```
