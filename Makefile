.POSIX:
.SUFFIXES:

GO ?= go
RM ?= rm
GOFLAGS ?=
PREFIX ?= /usr/local
BINDIR ?= bin

all: sif

sif: 
	$(GO) build $(GOFLAGS) ./cmd/sif

clean:
	$(RM) -rf sif

install:
	mkdir -p $(DESTDIR)$(PREFIX)/$(BINDIR)
	cp -f sif $(DESTDIR)$(PREFIX)/$(BINDIR)

uninstall:
	$(RM) $(DESTDIR)$(PREFIX)/$(BINDIR)/sif

.PHONY: all sif clean install uninstall