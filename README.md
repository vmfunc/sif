<div align="center">

```
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀                                                                    :
:   ▄█ █ █▀    blazing-fast pentesting suite                                    :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
```

[![go version](https://img.shields.io/github/go-mod/go-version/dropalldatabases/sif?style=flat-square&color=00ADD8)](https://go.dev/)
[![build](https://img.shields.io/github/actions/workflow/status/dropalldatabases/sif/go.yml?style=flat-square)](https://github.com/dropalldatabases/sif/actions)
[![license](https://img.shields.io/badge/license-BSD--3--Clause-blue?style=flat-square)](LICENSE)

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

grab the latest binary from [releases](https://github.com/dropalldatabases/sif/releases).

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

## contributors

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://vmfunc.re"><img src="https://avatars.githubusercontent.com/u/59031302?v=4?s=100" width="100px;" alt="mel"/><br /><sub><b>mel</b></sub></a><br /><a href="#maintenance-vmfunc" title="Maintenance">🚧</a> <a href="#mentoring-vmfunc" title="Mentoring">🧑‍🏫</a> <a href="#projectManagement-vmfunc" title="Project Management">📆</a> <a href="#security-vmfunc" title="Security">🛡️</a> <a href="#test-vmfunc" title="Tests">⚠️</a> <a href="#business-vmfunc" title="Business development">💼</a> <a href="#code-vmfunc" title="Code">💻</a> <a href="#design-vmfunc" title="Design">🎨</a> <a href="#financial-vmfunc" title="Financial">💵</a> <a href="#ideas-vmfunc" title="Ideas, Planning, & Feedback">🤔</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://projectdiscovery.io"><img src="https://avatars.githubusercontent.com/u/50994705?v=4?s=100" width="100px;" alt="ProjectDiscovery"/><br /><sub><b>ProjectDiscovery</b></sub></a><br /><a href="#platform-projectdiscovery" title="Packaging/porting to new platform">📦</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/macdoos"><img src="https://avatars.githubusercontent.com/u/127897805?v=4?s=100" width="100px;" alt="macdoos"/><br /><sub><b>macdoos</b></sub></a><br /><a href="#code-macdoos" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://epitech.eu"><img src="https://avatars.githubusercontent.com/u/75166283?v=4?s=100" width="100px;" alt="Matthieu Witrowiez"/><br /><sub><b>Matthieu Witrowiez</b></sub></a><br /><a href="#ideas-D3adPlays" title="Ideas, Planning, & Feedback">🤔</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/tessa-u-k"><img src="https://avatars.githubusercontent.com/u/109355732?v=4?s=100" width="100px;" alt="tessa "/><br /><sub><b>tessa </b></sub></a><br /><a href="#infra-tessa-u-k" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a> <a href="#question-tessa-u-k" title="Answering Questions">💬</a> <a href="#userTesting-tessa-u-k" title="User Testing">📓</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/xyzeva"><img src="https://avatars.githubusercontent.com/u/133499694?v=4?s=100" width="100px;" alt="Eva"/><br /><sub><b>Eva</b></sub></a><br /><a href="#blog-xyzeva" title="Blogposts">📝</a> <a href="#content-xyzeva" title="Content">🖋</a> <a href="#research-xyzeva" title="Research">🔬</a> <a href="#security-xyzeva" title="Security">🛡️</a> <a href="#test-xyzeva" title="Tests">⚠️</a> <a href="#code-xyzeva" title="Code">💻</a></td>
    </tr>
  </tbody>
</table>

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
