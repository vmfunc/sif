<div align="center">

<img src="assets/banner.png" alt="sif" width="600">

<br><br>

[![go version](https://img.shields.io/github/go-mod/go-version/vmfunc/sif?style=flat-square&color=00ADD8)](https://go.dev/)
[![build](https://img.shields.io/github/actions/workflow/status/vmfunc/sif/go.yml?style=flat-square)](https://github.com/vmfunc/sif/actions)
[![license](https://img.shields.io/badge/license-BSD--3--Clause-blue?style=flat-square)](LICENSE)
[![discord](https://img.shields.io/badge/discord-join-5865F2?style=flat-square&logo=discord&logoColor=white)](https://discord.gg/sifcli)

**[install](#install) · [usage](#usage) · [modules](#modules) · [contribute](#contribute)**

</div>

---

## what is sif?

sif is a modular pentesting toolkit written in go. it's designed to be fast, concurrent, and extensible. run multiple scan types against targets with a single command.

```bash
./sif -u https://example.com -all
```

## install

### from releases

grab the latest binary from [releases](https://github.com/vmfunc/sif/releases).

### from source

```bash
git clone https://github.com/dropalldatabases/sif.git
cd sif
make
```

requires go 1.23+

## usage

```bash
# basic scan
./sif -u https://example.com

# directory fuzzing
./sif -u https://example.com -dirlist medium

# subdomain enumeration
./sif -u https://example.com -dnslist medium

# port scanning
./sif -u https://example.com -ports common

# javascript framework detection + cloud misconfig
./sif -u https://example.com -js -c3

# shodan host intelligence (requires SHODAN_API_KEY env var)
./sif -u https://example.com -shodan

# sql recon + lfi scanning
./sif -u https://example.com -sql -lfi

# framework detection (with cve lookup)
./sif -u https://example.com -framework

# everything
./sif -u https://example.com -all
```

run `./sif -h` for all options.

## modules

| module | description |
|--------|-------------|
| `dirlist` | directory and file fuzzing |
| `dnslist` | subdomain enumeration |
| `ports` | port and service scanning |
| `nuclei` | vulnerability scanning with nuclei templates |
| `dork` | automated google dorking |
| `js` | javascript framework detection (next.js, supabase) |
| `c3` | cloud storage misconfiguration scanning |
| `headers` | http header analysis |
| `takeover` | subdomain takeover detection |
| `cms` | cms detection |
| `whois` | whois lookups |
| `git` | exposed git repository detection |
| `shodan` | shodan host intelligence (requires SHODAN_API_KEY) |
| `sql` | sql admin panel and error disclosure detection |
| `lfi` | local file inclusion vulnerability scanning |
| `framework` | web framework detection with version + cve lookup |

## contribute

contributions welcome. see [contributing.md](CONTRIBUTING.md) for guidelines.

```bash
# format
gofmt -w .

# lint
golangci-lint run

# test
go test ./...
```

## community

join our discord for support, feature discussions, and pentesting tips:

[![discord](https://img.shields.io/badge/join%20our%20discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/sifcli)

## contributors

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

## acknowledgements

- [projectdiscovery](https://projectdiscovery.io/) for nuclei and other security tools
- [shodan](https://www.shodan.io/) for infrastructure intelligence

---

<div align="center">
  <sub>bsd 3-clause license · made by vmfunc, xyzeva, and contributors</sub>
</div>
