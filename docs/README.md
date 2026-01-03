# sif documentation

welcome to the sif documentation. sif is a modular pentesting toolkit designed to be fast, concurrent, and extensible.

## table of contents

### getting started

- [installation](installation.md) - how to install sif
- [quickstart](quickstart.md) - get up and running in minutes
- [usage](usage.md) - command line options and examples

### features

- [scans](scans.md) - built-in security scans
- [modules](modules.md) - yaml module system and custom modules

### reference

- [configuration](configuration.md) - runtime configuration options
- [api mode](api-mode.md) - json output for automation

### contributing

- [development](development.md) - setting up a dev environment
- [writing modules](modules.md#writing-modules) - create your own modules

---

## quick links

```bash
# install
git clone https://github.com/dropalldatabases/sif.git && cd sif && make

# basic scan
./sif -u https://example.com

# list modules
./sif -lm

# run all modules
./sif -u https://example.com -am

# help
./sif -h
```

## support

- [github issues](https://github.com/vmfunc/sif/issues) - bug reports and feature requests
- [discord](https://discord.gg/sifcli) - community chat
