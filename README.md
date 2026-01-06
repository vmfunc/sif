<div align="center">

<img src="assets/banner.png" alt="sif" width="600">

<br><br>

[![go version](https://img.shields.io/github/go-mod/go-version/vmfunc/sif?style=flat-square&color=00ADD8)](https://go.dev/)
[![build](https://img.shields.io/github/actions/workflow/status/vmfunc/sif/go.yml?style=flat-square)](https://github.com/vmfunc/sif/actions)
[![license](https://img.shields.io/badge/license-BSD--3--Clause-blue?style=flat-square)](LICENSE)
[![aur](https://img.shields.io/aur/version/sif?style=flat-square&logo=archlinux&logoColor=white&color=1793D1)](https://aur.archlinux.org/packages/sif)
[![homebrew](https://img.shields.io/badge/homebrew-tap-FBB040?style=flat-square&logo=homebrew&logoColor=white)](https://github.com/vmfunc/homebrew-sif)
[![apt](https://img.shields.io/badge/apt-cloudsmith-2A5ADF?style=flat-square&logo=debian&logoColor=white)](https://cloudsmith.io/~sif/repos/deb/packages/)
[![discord](https://img.shields.io/badge/discord-join-5865F2?style=flat-square&logo=discord&logoColor=white)](https://discord.gg/sifcli)

**[install](#install) · [usage](#usage) · [modules](#modules) · [docs](docs/) · [contribute](#contribute)**

</div>

---

## what is sif?

sif is a modular pentesting toolkit written in go. it's designed to be fast, concurrent, and extensible. run multiple scan types against targets with a single command.

```bash
./sif -u https://example.com -all
```

## install

### homebrew (macos)

```bash
brew tap vmfunc/sif
brew install sif
```

### arch linux (aur)

install using your preferred aur helper:

```bash
yay -S sif
# or
paru -S sif
```

### debian/ubuntu (apt)

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/sif/deb/setup.deb.sh' | sudo -E bash
sudo apt-get install sif
```

### from releases

grab the latest binary from [releases](https://github.com/vmfunc/sif/releases).

### from source

```bash
git clone https://github.com/vmfunc/sif.git
cd sif
make
```

requires go 1.23+

### aur (manual install)

```bash
git clone https://aur.archlinux.org/sif.git
cd sif
makepkg -si
```

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

sif has a modular architecture. modules are defined in yaml and can be extended by users.

### built-in scan flags

| flag | description |
|------|-------------|
| `-dirlist` | directory and file fuzzing (small/medium/large) |
| `-dnslist` | subdomain enumeration (small/medium/large) |
| `-ports` | port scanning (common/full) |
| `-nuclei` | vulnerability scanning with nuclei templates |
| `-dork` | automated google dorking |
| `-js` | javascript analysis |
| `-c3` | cloud storage misconfiguration |
| `-headers` | http header analysis |
| `-st` | subdomain takeover detection |
| `-cms` | cms detection |
| `-whois` | whois lookups |
| `-git` | exposed git repository detection |
| `-shodan` | shodan lookup (requires SHODAN_API_KEY) |
| `-sql` | sql recon |
| `-lfi` | local file inclusion |
| `-framework` | framework detection with cve lookup |

### yaml modules

list available modules:

```bash
./sif -lm
```

run specific modules:

```bash
# run by id
./sif -u https://example.com -m sqli-error-based,xss-reflected

# run by tag
./sif -u https://example.com -mt owasp-top10

# run all modules
./sif -u https://example.com -am
```

### custom modules

create your own modules in `~/.config/sif/modules/`. modules use a yaml format similar to nuclei templates:

```yaml
id: my-custom-check
info:
  name: my custom security check
  author: you
  severity: medium
  description: checks for something specific
  tags: [custom, recon]

type: http

http:
  method: GET
  paths:
    - "{{BaseURL}}/admin"
    - "{{BaseURL}}/login"

  matchers:
    - type: status
      status:
        - 200

    - type: word
      part: body
      words:
        - "admin panel"
        - "login"
      condition: or
```

see [docs/modules.md](docs/modules.md) for the full module format.

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
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://vmfunc.re"><img src="https://avatars.githubusercontent.com/u/59031302?v=4?s=100" width="100px;" alt="Celeste Hickenlooper"/><br /><sub><b>Celeste Hickenlooper</b></sub></a><br /><a href="#maintenance-vmfunc" title="Maintenance">🚧</a> <a href="#mentoring-vmfunc" title="Mentoring">🧑‍🏫</a> <a href="#projectManagement-vmfunc" title="Project Management">📆</a> <a href="#security-vmfunc" title="Security">🛡️</a> <a href="https://github.com/lunchcat/sif/commits?author=vmfunc" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://projectdiscovery.io"><img src="https://avatars.githubusercontent.com/u/50994705?v=4?s=100" width="100px;" alt="ProjectDiscovery"/><br /><sub><b>ProjectDiscovery</b></sub></a><br /><a href="#platform-projectdiscovery" title="Packaging/porting to new platform">📦</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/macdoos"><img src="https://avatars.githubusercontent.com/u/127897805?v=4?s=100" width="100px;" alt="macdoos"/><br /><sub><b>macdoos</b></sub></a><br /><a href="https://github.com/lunchcat/sif/commits?author=macdoos" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://epitech.eu"><img src="https://avatars.githubusercontent.com/u/75166283?v=4?s=100" width="100px;" alt="Matthieu Witrowiez"/><br /><sub><b>Matthieu Witrowiez</b></sub></a><br /><a href="#ideas-D3adPlays" title="Ideas, Planning, & Feedback">🤔</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/tessa-u-k"><img src="https://avatars.githubusercontent.com/u/109355732?v=4?s=100" width="100px;" alt="tessa "/><br /><sub><b>tessa </b></sub></a><br /><a href="#infra-tessa-u-k" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a> <a href="#question-tessa-u-k" title="Answering Questions">💬</a> <a href="#userTesting-tessa-u-k" title="User Testing">📓</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/xyzeva"><img src="https://avatars.githubusercontent.com/u/133499694?v=4?s=100" width="100px;" alt="Eva"/><br /><sub><b>Eva</b></sub></a><br /><a href="#blog-xyzeva" title="Blogposts">📝</a> <a href="#content-xyzeva" title="Content">🖋</a> <a href="#research-xyzeva" title="Research">🔬</a> <a href="#security-xyzeva" title="Security">🛡️</a> <a href="https://github.com/lunchcat/sif/commits?author=xyzeva" title="Tests">⚠️</a> <a href="https://github.com/lunchcat/sif/commits?author=xyzeva" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/vxfemboy"><img src="https://avatars.githubusercontent.com/u/79362520?v=4?s=100" width="100px;" alt="Zoa Hickenlooper"/><br /><sub><b>Zoa Hickenlooper</b></sub></a><br /><a href="https://github.com/lunchcat/sif/commits?author=vxfemboy" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/0xatrilla"><img src="https://avatars.githubusercontent.com/u/107285362?v=4?s=100" width="100px;" alt="acxtrilla"/><br /><sub><b>acxtrilla</b></sub></a><br /><a href="#platform-0xatrilla" title="Packaging/porting to new platform">📦</a></td>
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
