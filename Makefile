# make        build everything
# make test   run codes A, B and C in all three languages, then the D round trip
PREFIX := $(CURDIR)/third_party/prefix
SODIUM_LIBDIR := $(shell pkg-config --variable=libdir libsodium)
# Set inline: macOS strips DYLD_* from the environment of /bin/sh, so an export would not reach Python.
LIBPATH := $(PREFIX)/lib:$(SODIUM_LIBDIR)
PY := DYLD_FALLBACK_LIBRARY_PATH=$(LIBPATH) LD_LIBRARY_PATH=$(LIBPATH) .venv/bin/python
PYTHON ?= python3
R := 0100000000000000000000000000000000000000000000000000000000000000
K := 0200000000000000000000000000000000000000000000000000000000000000

.PHONY: all deps python cpp rust test oprf-vectors clean

all: deps python cpp rust

deps: $(PREFIX)/include/opaque.h
$(PREFIX)/include/opaque.h: scripts/build-deps.sh
	scripts/build-deps.sh

python: deps
	[ -x .venv/bin/python ] || $(PYTHON) -m venv .venv
	$(PY) -m pip install -q pysodium==0.7.18 ./third_party/libopaque/python

cpp: deps
	cmake -S cpp -B build/cpp -DCMAKE_BUILD_TYPE=Release
	cmake --build build/cpp

rust:
	cargo build --release --manifest-path rust/Cargo.toml

# The teaching OPRF must give the same output in every language for fixed r and k.
oprf-vectors:
	@a=$$($(PY) python/oprf.py hunter2 --r $(R) --k $(K) | grep 'F(k'); \
	 b=$$(build/cpp/oprf hunter2 $(R) $(K) | grep 'F(k'); \
	 c=$$(rust/target/release/oprf hunter2 $(R) $(K) | grep 'F(k'); \
	 echo "$$a"; [ "$$a" = "$$b" ] && [ "$$a" = "$$c" ] && echo "OPRF output identical in Python, C++ and Rust"

test: all oprf-vectors
	@echo "== Python";  $(PY) python/opaque_flow.py
	@echo "== C++";     build/cpp/opaque_flow
	@echo "== Rust";    rust/target/release/opaque_flow
	scripts/interop.sh

clean:
	rm -rf build rust/target .venv third_party
