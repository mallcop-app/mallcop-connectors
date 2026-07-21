# mallcop-connectors — build/install namespaced connector binaries.
#
# Each cmd/<source> package builds to `mallcop-connector-<source>` so the
# binaries do NOT collide with the real vendor CLIs (bare `aws`, `gcp`, `okta`,
# ...) already on a user's $PATH. The Go source is unchanged: the namespace is a
# build-output rename only (`go build -o mallcop-connector-<source> ./cmd/<source>`).
#
# The stdout JSONL + --since/--cursor contract is independent of the binary name
# (flags are parsed from os.Args[1:], output goes to os.Stdout), so mallcop's
# ExecConnector can invoke `mallcop-connector-<source>` unchanged.

GO      ?= go
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
DISTDIR ?= dist
PREFIXED = mallcop-connector-

SOURCES = aws azure cloudwatch coinbase gcp github guardduty loganalytics m365 mercury nostr okta
BINARIES = $(addprefix $(DISTDIR)/$(PREFIXED),$(SOURCES))

.PHONY: all build install uninstall clean test list

all: build

## build: compile every connector to dist/mallcop-connector-<source>
build: $(BINARIES)

$(DISTDIR)/$(PREFIXED)%: cmd/% $(wildcard cmd/%/*.go)
	@mkdir -p $(DISTDIR)
	$(GO) build -o $@ ./$<

## install: build then copy binaries into $(BINDIR) (override with PREFIX/BINDIR)
install: build
	@mkdir -p $(BINDIR)
	@for s in $(SOURCES); do \
		echo "install $(DISTDIR)/$(PREFIXED)$$s -> $(BINDIR)/$(PREFIXED)$$s"; \
		install -m 0755 $(DISTDIR)/$(PREFIXED)$$s $(BINDIR)/$(PREFIXED)$$s; \
	done

## uninstall: remove installed connector binaries from $(BINDIR)
uninstall:
	@for s in $(SOURCES); do \
		echo "rm -f $(BINDIR)/$(PREFIXED)$$s"; \
		rm -f $(BINDIR)/$(PREFIXED)$$s; \
	done

## test: run the Go test suite
test:
	$(GO) test ./...

## list: print the installed binary names
list:
	@for s in $(SOURCES); do echo $(PREFIXED)$$s; done

## clean: remove build output
clean:
	rm -rf $(DISTDIR)
