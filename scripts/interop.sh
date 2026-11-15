#!/usr/bin/env bash
# Code D: the Python (libopaque) server against the C++ (libopaque) and Rust (opaque-ke) clients.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
port="${PORT:-8765}"
# macOS strips DYLD_* from bash's environment, so set the library path here.
lib="$root/third_party/prefix/lib:$(pkg-config --variable=libdir libsodium)"
export DYLD_FALLBACK_LIBRARY_PATH="$lib" LD_LIBRARY_PATH="$lib"
"$root/.venv/bin/python" "$root/python/server.py" "$port" &
server=$!
trap 'kill $server 2>/dev/null' EXIT
for _ in $(seq 50); do (echo > "/dev/tcp/127.0.0.1/$port") 2>/dev/null && break; sleep 0.1; done

pw="correct horse battery staple"
echo "== C++ client -> Python server";  "$root/build/cpp/client" alice "$pw" "$pw" "$port"
echo "== C++ client, wrong password";   "$root/build/cpp/client" bob "$pw" "$pw!" "$port"
echo "== Rust client -> Python server"; "$root/rust/target/release/client" carol "$pw" "$pw" "$port"
echo "== Rust client, wrong password";  "$root/rust/target/release/client" dave "$pw" "$pw!" "$port"

# One record, two implementations: C++ (libopaque) registers, Rust (opaque-ke) logs in.
echo "== C++ registers frank, Rust logs in"
"$root/build/cpp/client" frank "$pw" "$pw" "$port" > /dev/null
"$root/rust/target/release/client" frank "$pw" "$pw" "$port" --login-only
# The KSF runs only on the client, so it has to match across clients that share a record.
echo "== same, but Rust uses opaque-ke's default Argon2 parameters (expected to fail)"
if "$root/rust/target/release/client" frank "$pw" "$pw" "$port" --login-only --default-ksf; then
  echo "unexpected: a KSF mismatch authenticated"; exit 1
fi
