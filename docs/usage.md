# usage

complete guide to sif command line options.

## target options

### -u, --urls

specify target urls (comma-separated):

```bash
./sif -u https://example.com
./sif -u https://site1.com,https://site2.com
```

### -f, --file

read targets from a file (one url per line):

```bash
./sif -f targets.txt
```

## scan options

### directory fuzzing

`-dirlist <size>` - fuzz for directories and files

sizes: `small`, `medium`, `large`

```bash
./sif -u https://example.com -dirlist medium
```

### subdomain enumeration

`-dnslist <size>` - enumerate subdomains

sizes: `small`, `medium`, `large`

```bash
./sif -u https://example.com -dnslist small
```

### port scanning

`-ports <scope>` - scan for open ports

scopes: `common` (top ports), `full` (all ports)

```bash
./sif -u https://example.com -ports common
```

### google dorking

`-dork` - automated google dorking

```bash
./sif -u https://example.com -dork
```

### git repository detection

`-git` - check for exposed git repositories

```bash
./sif -u https://example.com -git
```

### nuclei scanning

`-nuclei` - run nuclei vulnerability templates

```bash
./sif -u https://example.com -nuclei
```

### javascript analysis

`-js` - analyze javascript files + secret and endpoint extraction

```bash
./sif -u https://example.com -js
```

### cms detection

`-cms` - detect content management systems

```bash
./sif -u https://example.com -cms
```

### http headers

`-headers` - dump the target's response headers

```bash
./sif -u https://example.com -headers
```

### security headers

`-sh` - flag missing/weak security headers (hsts, csp, x-frame-options, ...) and headers that leak server internals

```bash
./sif -u https://example.com -sh
```

### cloud storage

`-c3` - check for cloud storage misconfigurations

```bash
./sif -u https://example.com -c3
```

### subdomain takeover

`-st` - check for subdomain takeover vulnerabilities

requires `-dnslist` to be enabled

```bash
./sif -u https://example.com -dnslist small -st
```

### shodan lookup

`-shodan` - query shodan for host intelligence

requires `SHODAN_API_KEY` environment variable

```bash
export SHODAN_API_KEY=your-api-key
./sif -u https://example.com -shodan
```

### sql reconnaissance

`-sql` - detect sql admin panels and error disclosure

```bash
./sif -u https://example.com -sql
```

### lfi scanning

`-lfi` - local file inclusion vulnerability checks

```bash
./sif -u https://example.com -lfi
```

### cors probe

`-cors` - probe for cors misconfigurations (reflected/permissive origins)

```bash
./sif -u https://example.com -cors
```

### open redirect probe

`-redirect` - probe redirect-prone params for open redirects

```bash
./sif -u https://example.com/login?next=home -redirect
```

### reflected xss probe

`-xss` - inject a canary into params and report unescaped reflections

```bash
./sif -u https://example.com/search?q=test -xss
```

### framework detection

`-framework` - detect web frameworks with version and cve lookup

```bash
./sif -u https://example.com -framework
```

### whois lookup

`-whois` - perform whois lookups

```bash
./sif -u https://example.com -whois
```

### skip base scan

`-noscan` - skip the base url scan (robots.txt, etc)

```bash
./sif -u https://example.com -noscan -dirlist medium
```

## module options

### -lm, --list-modules

list all available modules:

```bash
./sif -lm
```

### -m, --modules

run specific modules by id (comma-separated):

```bash
./sif -u https://example.com -m sqli-error-based,xss-reflected
```

### -mt, --module-tags

run modules matching tags:

```bash
./sif -u https://example.com -mt owasp-top10
./sif -u https://example.com -mt injection
```

### -am, --all-modules

run all available modules:

```bash
./sif -u https://example.com -am
```

## runtime options

### -t, --timeout

http request timeout (default: 10s):

```bash
./sif -u https://example.com -t 30s
```

### --threads

number of concurrent threads (default: 10). values below 1 are clamped to 1:

```bash
./sif -u https://example.com --threads 20
```

### -l, --log

directory to save log files:

```bash
./sif -u https://example.com -l ./logs
```

### -d, --debug

enable debug logging:

```bash
./sif -u https://example.com -d
```

## http options

these apply to every outbound request across all scanners (proxy, custom headers, cookie and rate limiting share one client). a scanner that sets a header explicitly still wins over the global default.

### -proxy

route all traffic through a proxy. supports http, https and socks5 urls:

```bash
./sif -u https://example.com -proxy socks5://127.0.0.1:1080
```

### -H, --header

add a custom header to every request. repeatable or comma-separated, `"Key: Value"`:

```bash
./sif -u https://example.com -H "Authorization: Bearer tok" -H "X-Env: staging"
```

### -cookie

cookie header to send with every request:

```bash
./sif -u https://example.com -cookie "session=abc; theme=dark"
```

### -rate-limit

cap outbound requests per second (0 = unlimited, default 0):

```bash
./sif -u https://example.com -rate-limit 20
```

## api options

### -api

enable api mode for json output:

```bash
./sif -u https://example.com -api
```

output is a json object with scan results.

## commands

these run without scanning a target.

### version

print the sif version. release builds are stamped via ldflags, local `make` builds derive it from `git describe`, and `go install`ed builds read it from the module build info:

```bash
./sif version
```

### patchnote

show the latest release's notes, fetched from github (also `-pn`):

```bash
./sif patchnote
```

the first time you run a new release sif also prints that release's notes once. set `SIF_NO_PATCHNOTES=1` to disable that.

## examples

### quick recon

```bash
./sif -u https://example.com -framework -headers -git
```

### full scan

```bash
./sif -u https://example.com \
  -dirlist large \
  -dnslist medium \
  -ports full \
  -framework \
  -js \
  -headers \
  -cms \
  -git \
  -sql \
  -lfi \
  -cors \
  -redirect \
  -xss \
  -am
```

### ci/cd pipeline

```bash
./sif -u https://staging.example.com -api -am > results.json
```

### batch scanning

```bash
echo "https://site1.com
https://site2.com
https://site3.com" > targets.txt

./sif -f targets.txt -am -l ./logs
```
