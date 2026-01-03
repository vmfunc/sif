# quickstart

get up and running with sif in minutes.

## basic scan

run a basic scan against a target:

```bash
./sif -u https://example.com
```

this performs a base scan checking robots.txt, common files, and basic reconnaissance.

## add more scans

enable additional scan types with flags:

```bash
# directory fuzzing
./sif -u https://example.com -dirlist medium

# subdomain enumeration
./sif -u https://example.com -dnslist small

# port scanning
./sif -u https://example.com -ports common

# framework detection
./sif -u https://example.com -framework
```

## run modules

sif has a modular architecture with yaml-based security checks:

```bash
# list available modules
./sif -lm

# run all modules
./sif -u https://example.com -am

# run specific modules
./sif -u https://example.com -m sqli-error-based,xss-reflected

# run by tag
./sif -u https://example.com -mt owasp-top10
```

## multiple targets

scan multiple urls:

```bash
./sif -u https://site1.com,https://site2.com
```

or from a file:

```bash
./sif -f targets.txt
```

## save output

save results to a log directory:

```bash
./sif -u https://example.com -l ./logs
```

## json output

for automation, use api mode:

```bash
./sif -u https://example.com -api
```

## full scan example

run everything:

```bash
./sif -u https://example.com \
  -dirlist medium \
  -dnslist small \
  -ports common \
  -framework \
  -js \
  -headers \
  -git \
  -am \
  -l ./logs
```

## next steps

- [usage](usage.md) - all command line options
- [scans](scans.md) - detailed scan descriptions
- [modules](modules.md) - write custom modules
