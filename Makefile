.POSIX:
.SUFFIXES:

GO ?= go
RM ?= rm
GOFLAGS ?=
PREFIX ?= /usr/local
BINDIR ?= bin

all: check_go_version sif

check_go_version:
	@$(GO) version | grep -q "go1\.23\." || (echo "Please install the latest version of Go" && exit 1)

sif: check_go_version
	$(GO) build $(GOFLAGS) ./cmd/sif

clean:
	$(RM) -rf sif

install: check_go_version
	mkdir -p $(DESTDIR)$(PREFIX)/$(BINDIR)
	cp -f sif $(DESTDIR)$(PREFIX)/$(BINDIR)

uninstall:
	$(RM) $(DESTDIR)$(PREFIX)/$(BINDIR)/sif

.PHONY: all check_go_version sif clean install uninstall