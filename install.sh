#!/usr/bin/env sh
# install.sh — build and install the mallcop connectors as namespaced binaries.
#
# Each cmd/<source> package is built to `mallcop-connector-<source>` so the
# binaries do not collide with the real vendor CLIs (bare `aws`, `gcp`, `okta`,
# ...) on your $PATH. This is a build-output rename only — the Go source and the
# stdout JSONL + --since/--cursor contract are unchanged.
#
# Usage:
#   ./install.sh                 # build to ./dist and install to /usr/local/bin
#   PREFIX=$HOME/.local ./install.sh   # install to $HOME/.local/bin
#   BINDIR=$HOME/bin ./install.sh      # install to an explicit directory
#   DISTONLY=1 ./install.sh      # build to ./dist only, do not install
set -eu

GO="${GO:-go}"
DISTDIR="${DISTDIR:-dist}"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="${BINDIR:-$PREFIX/bin}"
PREFIXED="mallcop-connector-"
SOURCES="aws azure gcp github m365 okta"

cd "$(dirname "$0")"

mkdir -p "$DISTDIR"
for s in $SOURCES; do
	out="$DISTDIR/$PREFIXED$s"
	echo "build ./cmd/$s -> $out"
	"$GO" build -o "$out" "./cmd/$s"
done

if [ "${DISTONLY:-0}" = "1" ]; then
	echo "built binaries in $DISTDIR (DISTONLY set, not installing)"
	exit 0
fi

mkdir -p "$BINDIR"
for s in $SOURCES; do
	echo "install $DISTDIR/$PREFIXED$s -> $BINDIR/$PREFIXED$s"
	install -m 0755 "$DISTDIR/$PREFIXED$s" "$BINDIR/$PREFIXED$s"
done

echo "done. Ensure $BINDIR is on your \$PATH."
