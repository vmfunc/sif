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

`-js` - analyze javascript files

```bash
./sif -u https://example.com -js
```

### cms detection

`-cms` - detect content management systems

```bash
./sif -u https://example.com -cms
```

### http headers

`-headers` - analyze security headers

```bash
./sif -u https://example.com -headers
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

number of concurrent threads (default: 10):

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

## api options

### -api

enable api mode for json output:

```bash
./sif -u https://example.com -api
```

output is a json object with scan results.

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
