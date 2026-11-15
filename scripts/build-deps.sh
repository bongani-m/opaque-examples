#!/usr/bin/env bash
# Builds liboprf and libopaque at pinned commits into third_party/prefix.
# Needs libsodium >= 1.0.19 (Homebrew, or libsodium-dev on a recent distro) and pkg-config.
set -euo pipefail

LIBOPRF_COMMIT=f925b87759d06ac97abc5b926fe0e7d0668a05ce
LIBOPAQUE_COMMIT=6e9ac92f9a2289679e04b0b0c5fdc307bb3de54e

root="$(cd "$(dirname "$0")/.." && pwd)"
tp="$root/third_party"
prefix="$tp/prefix"
obj="$tp/build"
mkdir -p "$prefix/include/oprf" "$prefix/lib" "$obj"

fetch() { # name commit
  [ -d "$tp/$1" ] || git clone --quiet "https://github.com/stef/$1" "$tp/$1"
  git -C "$tp/$1" checkout --quiet "$2"
}
fetch liboprf "$LIBOPRF_COMMIT"
fetch libopaque "$LIBOPAQUE_COMMIT"

CC="${CC:-cc}"
SODIUM_CFLAGS="$(pkg-config --cflags libsodium)"
SODIUM_LIBS="$(pkg-config --libs libsodium)"
CFLAGS="-O2 -fPIC -std=c99 -Wall -Wno-unknown-attributes -Wno-unknown-warning-option $SODIUM_CFLAGS"

if [ "$(uname -s)" = Darwin ]; then
  ext=dylib
  soname() { echo "-Wl,-install_name,$prefix/lib/$1"; }
else
  ext=so
  soname() { echo "-Wl,-soname,$1"; }
fi

# liboprf: only the OPRF and threshold-OPRF parts that libopaque calls.
for f in oprf toprf utils; do
  $CC $CFLAGS -I"$tp/liboprf/src" -c "$tp/liboprf/src/$f.c" -o "$obj/$f.o"
done
$CC -shared -o "$prefix/lib/liboprf.$ext" $(soname "liboprf.$ext") \
  "$obj/oprf.o" "$obj/toprf.o" "$obj/utils.o" $SODIUM_LIBS
cp "$tp/liboprf/src/"*.h "$prefix/include/oprf/"

# libopaque. A release build: never define NORANDOM (fixed nonces, for test vectors only).
for f in opaque common; do
  $CC $CFLAGS -I"$prefix/include" -c "$tp/libopaque/src/$f.c" -o "$obj/$f.o"
done
$CC -shared -o "$prefix/lib/libopaque.$ext" $(soname "libopaque.$ext") \
  "$obj/opaque.o" "$obj/common.o" -L"$prefix/lib" -loprf $SODIUM_LIBS
cp "$tp/libopaque/src/opaque.h" "$prefix/include/"

echo "built libopaque @ ${LIBOPAQUE_COMMIT:0:12} and liboprf @ ${LIBOPRF_COMMIT:0:12} into $prefix"
