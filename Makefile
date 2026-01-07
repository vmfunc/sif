# Copyright (c) 2024 vmfunc, xyzeva, lunchcat, and contributors
# SPDX-License-Identifier: MIT

.POSIX:
.SUFFIXES:

GO ?= go
RM ?= rm
GOFLAGS ?=
PREFIX ?= /usr/local
BINDIR ?= bin

define COPYRIGHT_ASCII
╭────────────────────────────────────────────────────────────╮
│                           _____________                    │
│                    __________(_)__  __/                    │
│                    __  ___/_  /__  /_                      │
│                    _(__  )_  / _  __/                      │
│                    /____/ /_/  /_/                         │
│                                                            │
╰────────────────────────────────────────────────────────────╯
Copyright (c) 2024 vmfunc, xyzeva, lunchcat, and contributors


endef
export COPYRIGHT_ASCII

define SUPPORT_MESSAGE


╭────────────────────────────────────────────────────────────╮
│                                                            │
│  🌟 Enjoying sif? Please consider:                         │
│                                                            │
│  • Starring our repo: https://github.com/vmfunc/sif        │
│                                                            │
│  Your support helps us continue improving sif!             │
│                                                            │
╰────────────────────────────────────────────────────────────╯
endef
export SUPPORT_MESSAGE

all: check_go_version sif
	@echo "✅ All tasks completed successfully! 🎉"
	@echo "$$SUPPORT_MESSAGE"

check_go_version:
	@echo "$$COPYRIGHT_ASCII"
	@echo "🔍 Checking Go version..."
	@$(GO) version | grep -E "go1\.[2-9][0-9]*\." || (echo "❌ Error: Please install the latest version of Go" && exit 1)
	@echo "✅ Go version check passed!"

sif: check_go_version
	@echo "🛠️ Building sif..."
	@echo "📁 Current directory: $$(pwd)"
	@echo "🔧 Go flags: $(GOFLAGS)"
	@echo "📦 Building package: ./cmd/sif"
	$(GO) build -v $(GOFLAGS) ./cmd/sif
	@echo "📊 Build info:"
	@$(GO) version -m sif
	@echo "✅ sif built successfully! 🚀"

clean:
	@echo "$$COPYRIGHT_ASCII"
	@echo "🧹 Cleaning up..."
	@$(RM) -rf sif
	@echo "✨ Cleanup complete!"

install: check_go_version
	@echo "$$COPYRIGHT_ASCII"
	@echo "📦 Installing sif..."
	@if [ "$$(uname)" != "Linux" ] && [ "$$(uname)" != "Darwin" ]; then \
		echo "❌ Error: This installation script is for UNIX systems only."; \
		exit 1; \
	fi
	@mkdir -p $(DESTDIR)$(PREFIX)/$(BINDIR) || (echo "🔒 Permission denied. Trying with sudo..." && sudo mkdir -p $(DESTDIR)$(PREFIX)/$(BINDIR))
	@cp -f sif $(DESTDIR)$(PREFIX)/$(BINDIR) || (echo "🔒 Permission denied. Trying with sudo..." && sudo cp -f sif $(DESTDIR)$(PREFIX)/$(BINDIR))
	@echo "✅ sif installed successfully! 🎊"

uninstall:
	@echo "$$COPYRIGHT_ASCII"
	@echo "🗑️ Uninstalling sif..."
	@if [ "$$(uname)" != "Linux" ] && [ "$$(uname)" != "Darwin" ]; then \
		echo "❌ Error: This uninstallation script is for UNIX systems only."; \
		exit 1; \
	fi
	@$(RM) $(DESTDIR)$(PREFIX)/$(BINDIR)/sif || (echo "🔒 Permission denied. Trying with sudo..." && sudo $(RM) $(DESTDIR)$(PREFIX)/$(BINDIR)/sif)
	@echo "✅ sif uninstalled successfully!"

.PHONY: all check_go_version sif clean install uninstall