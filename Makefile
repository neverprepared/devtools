BINARY  := devtools
PKG     := github.com/neverprepared/devtools
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X $(PKG)/internal/cli.version=$(VERSION)
PREFIX  ?= $(HOME)/.local

.PHONY: all build test vet fmt check install uninstall clean

all: check build

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

check: vet test

## install puts the binary on PATH. Use an absolute path in launchd/cron
## entries, since neither runs with your shell's PATH.
install:
	install -d $(PREFIX)/bin
	go build -ldflags "$(LDFLAGS)" -o $(PREFIX)/bin/$(BINARY) .
	@echo "installed $(PREFIX)/bin/$(BINARY)"

uninstall:
	rm -f $(PREFIX)/bin/$(BINARY)

clean:
	rm -rf bin
