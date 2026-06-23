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

### stdin (pipe mode)

when stdin is a pipe, sif reads one target per line from it, alongside any `-u`/`-f` targets. this lets sif slot into a unix pipeline:

```bash
subfinder -d example.com | sif -silent -probe | notify
```

### naked hosts

targets without a scheme default to `https://`; an explicit `http://`/`https://` is kept as given. any other scheme (`ftp://`, `file://`, ...) is rejected:

```bash
./sif -u example.com          # scanned as https://example.com
echo example.com | sif -probe # same, over stdin
```

## scan options

### directory fuzzing

`-dirlist <size>` - fuzz for directories and files

sizes: `small`, `medium`, `large`

```bash
./sif -u https://example.com -dirlist medium
```

#### response filters

modern apps serve a catch-all 200 for unknown routes, so a naive scan reports
every path. these ffuf-style filters cut the noise (a filter always wins over a
match):

- `-mc <codes>` - match only these status codes (comma list, e.g. `200,301`)
- `-fc <codes>` - filter out these status codes
- `-fs <sizes>` - filter out responses of these body sizes
- `-fw <counts>` - filter out responses with these word counts
- `-fr <regex>` - filter out responses whose body matches this regex

```bash
./sif -u https://example.com -dirlist medium -mc 200,301 -fs 1234
```

#### wildcard calibration

`-ac` probes a few paths that cannot exist, learns the soft-404 baseline
(status + size + words), and auto-drops any response matching it - so SPA
catch-all 200s stop flooding the output:

```bash
./sif -u https://example.com -dirlist medium -ac
```

#### custom wordlists and extensions

`-w <path|url>` overrides the size switch with your own list (local file or
remote url); `-e <exts>` appends each extension to every word, keeping the bare
word too:

```bash
./sif -u https://example.com -w /path/to/words.txt -e php,bak,env
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

### jwt analysis

`-jwt` - fetch the target once, harvest jwts from response headers, cookies and body, then analyze each one entirely offline

flags alg:none, the rs256->hs256 confusion surface, missing/expired exp, plaintext sensitive claims, and cracks a small bundled weak-hmac wordlist. no token is ever sent off-box.

```bash
./sif -u https://example.com -jwt
```

### openapi/swagger exposure

`-openapi` - probe the conventional spec paths (`/swagger.json`, `/openapi.json`, `/v3/api-docs`, ...), parse the first hit (json or yaml) and enumerate every path+method, flagging operations with no security requirement

```bash
./sif -u https://example.com -openapi
```

### favicon fingerprint

`-favicon` - fetch `/favicon.ico` (or the declared `<link rel=icon>`), compute the shodan-style mmh3 hash, match it against a bundled tech map and print the `http.favicon.hash:<n>` pivot query

```bash
./sif -u https://example.com -favicon
```

### framework detection

`-framework` - detect web frameworks with version and cve lookup

```bash
./sif -u https://example.com -framework
```

### web crawler

`-crawl` - spider the target, following same-host links, scripts and forms

`-crawl-depth` - max recursion depth (default 2). respects robots.txt and stays on the target host.

```bash
./sif -u https://example.com -crawl -crawl-depth 3
```

### passive discovery

`-passive` - gather subdomains from certificate transparency (crt.sh, certspotter) and historical urls from the wayback machine

keyless and zero traffic to the target itself - all lookups hit third-party feeds.

```bash
./sif -u https://example.com -passive
```

### live-host probe

`-probe` - check whether the target is alive and report its final status, page title, server header, content-length and the redirect chain it walked

```bash
./sif -u https://example.com -probe
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

### --template

load a batch of scan settings from a template instead of passing each flag. the value is either a built-in preset or a local yaml file keyed by flag long-names:

```bash
./sif -u https://example.com --template recon
./sif -u https://example.com --template ./my-scans.yaml
```

built-in presets:

- `minimal`: liveness and fingerprint only (probe, headers, favicon)
- `recon`: broad non-intrusive discovery, no attack payloads
- `full`: every scan except the api-key ones (shodan, securitytrails), including the intrusive probes (xss, sql, lfi, redirect)

`full` sends attack payloads, so only run it against targets you are authorized to test.

a local template lists flag long-names, for example:

```yaml
cms: true
dirlist: medium
threads: 20
```

flags passed on the command line take precedence over the template, so `--template recon -xss` runs the recon preset with an added xss probe.

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

## output options

write the collected findings out to a file after the scan. both formats can be requested in the same run.

### -sarif

write a sarif 2.1.0 report (one run, tool `sif`, one result per finding). ingestable by github code scanning and other sarif consumers:

```bash
./sif -u https://example.com -headers -cors -sarif out.sarif
```

### -md, --markdown

write a readable markdown report grouped by target, then by module:

```bash
./sif -u https://example.com -headers -cors -md report.md
```

### -silent

plain output for pipelines: all banner/spinner/log chrome goes to stderr and stdout carries one normalized finding per line, formatted `[severity] target module title`. implies non-interactive (no spinners), so a downstream consumer sees nothing but findings:

```bash
subfinder -d example.com | sif -silent -probe -sh | notify
```

### -diff

turn a re-scan into a monitor. sif snapshots each target's normalized findings to a json file under the store dir; on the next run it loads that snapshot, diffs the current findings against it by finding key, and prints only the delta (`+ new` for findings that appeared, `- gone` for findings that vanished). it always rewrites the snapshot afterwards, so each run compares against the previous one.

the first run for a target has no snapshot, so every finding shows as `+ new`. when nothing changed, sif notes that and writes a fresh snapshot anyway.

```bash
# baseline, then re-scan and see only what moved
./sif -u https://example.com -sh -cors -diff
./sif -u https://example.com -sh -cors -diff
```

the delta is chrome, not the findings stream: under `-silent` it rides stderr with the rest of the chrome, leaving stdout for the full findings.

### -store

snapshot directory for `-diff`. precedence when unset: the `-log` dir if one is given, else `<user-config>/sif/state` (`$XDG_CONFIG_HOME/sif/state` on linux, `~/Library/Application Support/sif/state` on macos). one sanitized file per target, created at `0750`, written `0600`.

```bash
./sif -u https://example.com -sh -diff -store ./snapshots
```


## notify options

ship findings to a chat/webhook sink after the scan. every provider is a single POST through the shared http client, so the global proxy/rate-limit/header config applies. with nothing configured, `-notify` is a silent no-op.

### -notify

enable delivery to every configured provider:

```bash
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
./sif -u https://example.com -cors -xss -notify
```

### -notify-severity

minimum severity to send: `info`, `low`, `medium`, `high` or `critical` (default `medium`). findings below the floor are dropped, so info-level recon noise doesn't flood a channel. an unrecognized value falls back to `medium`:

```bash
./sif -u https://example.com -cors -notify -notify-severity high
```

### -notify-config

path to a yaml config that overrides the env vars per-field. the keys match [projectdiscovery/notify](https://github.com/projectdiscovery/notify) so an existing config ports over:

```yaml
slack_webhook_url: https://hooks.slack.com/services/...
discord_webhook_url: https://discord.com/api/webhooks/...
telegram_api_key: 123456:abcdef
telegram_chat_id: "987654"
webhook_url: https://example.internal/sif-findings
```

```bash
./sif -u https://example.com -cors -notify -notify-config notify.yaml
```

providers are resolved env-first, then overlaid by the yaml file:

| env var | yaml key | provider |
|---------|----------|----------|
| `SLACK_WEBHOOK_URL` | `slack_webhook_url` | slack incoming webhook |
| `DISCORD_WEBHOOK_URL` | `discord_webhook_url` | discord webhook |
| `TELEGRAM_BOT_TOKEN` | `telegram_api_key` | telegram bot api (needs chat id too) |
| `TELEGRAM_CHAT_ID` | `telegram_chat_id` | telegram destination chat |
| `NOTIFY_WEBHOOK_URL` | `webhook_url` | generic json webhook (structured findings) |

slack/discord/telegram receive a fixed-width finding block; the generic webhook receives structured json (`{count, findings[]}`) for downstream automation.

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
