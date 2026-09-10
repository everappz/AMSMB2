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
# Second server: authenticated (creds) + signing, so SMB signing can be exercised (signing needs a
# session key, which anonymous sessions don't have).
PORT2=$((PORT + 1))
ROOT2="$(mktemp -d /tmp/amsmb2-share.XXXXXX)"
echo "seed" > "$ROOT2/readme.txt"
SMB_TEST_USER="smbtester"; SMB_TEST_PASS="Passw0rd!"
"$BUILD/server_bin" "$ROOT2" "$PORT2" 1 1 "$SMB_TEST_USER" "$SMB_TEST_PASS" > "$BUILD/server2.log" 2>&1 &
SRVPID2=$!
# Third server: authenticated + SMB3 encryption required (argv[7]=1), so seal can be exercised.
PORT3=$((PORT + 2))
ROOT3="$(mktemp -d /tmp/amsmb2-share.XXXXXX)"
echo "seed" > "$ROOT3/readme.txt"
"$BUILD/server_bin" "$ROOT3" "$PORT3" 1 1 "$SMB_TEST_USER" "$SMB_TEST_PASS" 1 > "$BUILD/server3.log" 2>&1 &
SRVPID3=$!
trap 'kill $SRVPID $SRVPID2 $SRVPID3 2>/dev/null || true; rm -rf "$BUILD" "$ROOT" "$ROOT2" "$ROOT3"' EXIT
for _ in $(seq 1 50); do grep -q "SERVER UP" "$BUILD/server.log" 2>/dev/null && break; sleep 0.1; done
for _ in $(seq 1 50); do grep -q "SERVER UP" "$BUILD/server2.log" 2>/dev/null && break; sleep 0.1; done
for _ in $(seq 1 50); do grep -q "SERVER UP" "$BUILD/server3.log" 2>/dev/null && break; sleep 0.1; done

echo "== smoke test =="
"$BUILD/client_bin" "127.0.0.1:$PORT"

echo ""
echo "== comprehensive suite (30 tests) =="
"$BUILD/client_tests" "127.0.0.1:$PORT"

echo ""
echo "== share enumeration (srvsvc NetrShareEnum) =="
"$BUILD/client_shareenum" "127.0.0.1:$PORT"

echo ""
echo "== signed pass: authenticated client REQUIRES SMB signing (server signing_enabled=1) =="
SMB_USER="$SMB_TEST_USER" SMB_PASSWORD="$SMB_TEST_PASS" SMB_SIGNING=required "$BUILD/client_bin" "127.0.0.1:$PORT2"
echo ""
echo "== signed comprehensive suite (30 tests, every PDU signed + verified) =="
SMB_USER="$SMB_TEST_USER" SMB_PASSWORD="$SMB_TEST_PASS" SMB_SIGNING=required "$BUILD/client_tests" "127.0.0.1:$PORT2"

echo ""
echo "== encrypted pass: authenticated client REQUIRES SMB3 seal (server encryption_enabled=1) =="
SMB_USER="$SMB_TEST_USER" SMB_PASSWORD="$SMB_TEST_PASS" SMB_ENCRYPTED=1 "$BUILD/client_bin" "127.0.0.1:$PORT3"
echo ""
echo "== encrypted comprehensive suite (30 tests, every PDU AES-CCM sealed) =="
SMB_USER="$SMB_TEST_USER" SMB_PASSWORD="$SMB_TEST_PASS" SMB_ENCRYPTED=1 "$BUILD/client_tests" "127.0.0.1:$PORT3"
