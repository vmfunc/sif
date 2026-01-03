# installation

## from releases

download the latest binary for your platform from [releases](https://github.com/vmfunc/sif/releases).

### linux

```bash
# download
curl -LO https://github.com/vmfunc/sif/releases/latest/download/sif-linux-amd64

# make executable
chmod +x sif-linux-amd64

# move to path (optional)
sudo mv sif-linux-amd64 /usr/local/bin/sif
```

### macos

```bash
# intel
curl -LO https://github.com/vmfunc/sif/releases/latest/download/sif-macos-amd64

# apple silicon
curl -LO https://github.com/vmfunc/sif/releases/latest/download/sif-macos-arm64

chmod +x sif-macos-*
sudo mv sif-macos-* /usr/local/bin/sif
```

### windows

download `sif-windows-amd64.exe` from releases and add to your PATH.

## from source

requires go 1.23+

```bash
git clone https://github.com/dropalldatabases/sif.git
cd sif
make
```

the binary will be created in the current directory.

### install to system

```bash
sudo make install
```

this installs to `/usr/local/bin/sif`.

### uninstall

```bash
sudo make uninstall
```

## verify installation

```bash
./sif -h
```

you should see the help output with available flags.

## updating

### from releases

download the new binary and replace the old one.

### from source

```bash
cd sif
git pull
make clean
make
```

## modules directory

sif looks for modules in these locations:

- **built-in**: `modules/` directory next to the sif binary
- **user modules**: `~/.config/sif/modules/` (linux/macos) or `%LOCALAPPDATA%\sif\modules\` (windows)

user modules override built-in modules with the same id.
