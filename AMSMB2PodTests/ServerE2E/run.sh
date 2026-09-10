#!/bin/bash
#
# End-to-end test for the AMSMB2 ObjC SMB server (AMSMB2Server).
#
# Because libsmb2 keeps a *global* list of active contexts, a client and a
# server cannot share one process (the serve loop would service the client's
# context). So this test uses two separate binaries:
#
#   server_bin  — AMSMB2Server + a filesystem-backed delegate over a temp dir
#   client_bin  — a plain libsmb2 client that drives browse/read/write/rename/…
#
# Both link a locally-built static libsmb2 from Dependencies/libsmb2. Run:
#
#   ./run.sh
#
# Exit code is 0 when every client assertion passes.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
LSMB="$REPO/Dependencies/libsmb2"
OBJC="$REPO/AMSMB2ObjC"
SDK="$(xcrun --show-sdk-path)"
BUILD="$(mktemp -d /tmp/amsmb2-e2e.XXXXXX)"
PORT="${1:-8445}"

echo "== building libsmb2 =="
mkdir -p "$BUILD/obj"
for f in "$LSMB"/lib/*.c; do
  clang -c "$f" -o "$BUILD/obj/$(basename "$f" .c).o" \
    -I "$LSMB/include" -I "$LSMB/include/apple" -I "$LSMB/include/smb2" -I "$LSMB/lib" \
    -D_U_='__attribute__((unused))' -DHAVE_CONFIG_H=1 -isysroot "$SDK" -Wno-everything
done
ar rcs "$BUILD/libsmb2.a" "$BUILD"/obj/*.o

echo "== building server + client =="
clang -fobjc-arc -o "$BUILD/server_bin" \
  "$HERE/server_main.m" "$OBJC/AMSMB2Server.m" "$OBJC/SMB2Helpers.m" "$BUILD/libsmb2.a" \
  -I "$LSMB/include" -I "$OBJC" -DHAVE_STDINT_H=1 -DHAVE_TIME_H=1 \
  -isysroot "$SDK" -framework Foundation -framework Security
clang -o "$BUILD/client_bin" "$HERE/client_main.c" "$BUILD/libsmb2.a" \
  -I "$LSMB/include" -isysroot "$SDK" -framework Foundation -framework Security
clang -o "$BUILD/client_tests" "$HERE/client_tests.c" "$BUILD/libsmb2.a" \
  -I "$LSMB/include" -isysroot "$SDK" -framework Foundation -framework Security
clang -o "$BUILD/client_shareenum" "$HERE/client_shareenum.c" "$BUILD/libsmb2.a" \
  -I "$LSMB/include" -isysroot "$SDK" -framework Foundation -framework Security

echo "== running server on 127.0.0.1:$PORT =="
ROOT="$(mktemp -d /tmp/amsmb2-share.XXXXXX)"
echo "seed" > "$ROOT/readme.txt"
"$BUILD/server_bin" "$ROOT" "$PORT" 1 1 > "$BUILD/server.log" 2>&1 &
SRVPID=$!
trap 'kill $SRVPID 2>/dev/null || true; rm -rf "$BUILD" "$ROOT"' EXIT
for _ in $(seq 1 50); do grep -q "SERVER UP" "$BUILD/server.log" 2>/dev/null && break; sleep 0.1; done

echo "== smoke test =="
"$BUILD/client_bin" "127.0.0.1:$PORT"

echo ""
echo "== comprehensive suite (30 tests) =="
"$BUILD/client_tests" "127.0.0.1:$PORT"

echo ""
echo "== share enumeration (srvsvc NetrShareEnum) =="
"$BUILD/client_shareenum" "127.0.0.1:$PORT"
