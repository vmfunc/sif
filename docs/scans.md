# scans

detailed information about sif's built-in security scans.

## base scan

runs automatically unless `-noscan` is specified.

checks:
- robots.txt parsing
- common files (sitemap.xml, security.txt, etc)
- basic reconnaissance

## directory fuzzing (-dirlist)

brute-forces directories and files using wordlists.

### sizes

| size | entries | use case |
|------|---------|----------|
| small | ~1k | quick scan, low noise |
| medium | ~10k | balanced coverage |
| large | ~100k | thorough, takes longer |

### what it finds

- hidden directories (/admin, /backup, /config)
- backup files (.bak, .old, .zip)
- configuration files
- development artifacts

## subdomain enumeration (-dnslist)

discovers subdomains via dns brute-forcing.

### sizes

| size | entries | use case |
|------|---------|----------|
| small | ~1k | quick discovery |
| medium | ~10k | common subdomains |
| large | ~100k | comprehensive |

### what it finds

- dev/staging environments
- internal services
- forgotten subdomains
- api endpoints

## port scanning (-ports)

scans for open ports and identifies services.

### scopes

| scope | ports | description |
|-------|-------|-------------|
| common | top 1000 | most common services |
| full | 1-65535 | all ports, slow |

### what it finds

- web servers (80, 443, 8080)
- databases (3306, 5432, 27017)
- admin interfaces (8443, 9090)
- development servers

## framework detection (-framework)

identifies web frameworks and their versions.

### detects

- react, vue, angular, next.js
- django, flask, rails
- laravel, symfony, express
- wordpress, drupal, joomla

### features

- version detection
- cve lookup for known vulnerabilities
- confidence scoring

## javascript analysis (-js)

analyzes javascript files for security issues.

### finds

- api endpoints and keys
- hardcoded credentials
- internal urls
- framework configurations
- source maps

## http headers (-headers)

analyzes security headers.

### checks

- content-security-policy
- x-frame-options
- x-content-type-options
- strict-transport-security
- x-xss-protection
- permissions-policy

## cms detection (-cms)

identifies content management systems.

### detects

- wordpress (with version)
- drupal
- joomla
- magento
- shopify
- ghost

## git repository (-git)

checks for exposed git repositories.

### finds

- .git/HEAD
- .git/config
- .git/index
- source code exposure risk

## cloud storage (-c3)

checks for cloud storage misconfigurations.

### checks

- s3 bucket access
- azure blob storage
- gcp storage buckets
- open bucket policies

## subdomain takeover (-st)

detects subdomain takeover vulnerabilities.

requires `-dnslist` to enumerate subdomains first.

### checks

- dangling cname records
- unclaimed cloud services
- expired third-party services

## shodan lookup (-shodan)

queries shodan for host intelligence.

requires `SHODAN_API_KEY` environment variable.

### returns

- open ports
- services and versions
- known vulnerabilities
- ssl/tls info
- organization data

## sql reconnaissance (-sql)

detects sql-related exposures.

### finds

- admin panels (/phpmyadmin, /adminer)
- database error messages
- sql injection indicators

## lfi scanning (-lfi)

checks for local file inclusion vulnerabilities.

### tests

- path traversal (../)
- null byte injection
- common lfi payloads
- sensitive file disclosure

## whois lookup (-whois)

performs whois lookups on target domains.

### returns

- registrar info
- creation/expiration dates
- nameservers
- registrant info (if available)

## google dorking (-dork)

automated google dorking for target.

### searches

- indexed sensitive files
- exposed admin panels
- configuration files
- backup files
- error pages

## nuclei scanning (-nuclei)

runs nuclei vulnerability templates.

requires nuclei to be installed.

### templates

- cve detection
- misconfigurations
- exposures
- default credentials
