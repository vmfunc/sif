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

module type. currently only `http` is supported.

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

extract key-value pairs.

```yaml
extractors:
  - type: kv
    name: headers
    part: header
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
