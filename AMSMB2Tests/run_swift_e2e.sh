#!/bin/bash
#
# Runs the Swift SMB2Manager test-suite (AMSMB2Tests/SMB2ManagerTests) against
# our OWN ObjC AMSMB2Server, exercising the full client<->server round trip for
# three security postures:
#
#   1. plain      - anonymous, no signing, no encryption
#   2. signed     - authenticated, SMB signing REQUIRED
#   3. encrypted  - authenticated, SMB3 seal (AES-128-CCM) REQUIRED, 3.1.1
#
# libsmb2 keeps a global list of active contexts, so a client and a server
# cannot share one process. This launches server_bin (built from the ServerE2E
# harness) as a separate process and points `swift test` at 127.0.0.1 via the
# SMB_* env the Swift suite reads.
#
#   ./run_swift_e2e.sh
#
# Exit code is 0 only when every posture's suite passes.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
LSMB="$REPO/Dependencies/libsmb2"
OBJC="$REPO/AMSMB2ObjC"
E2E="$REPO/AMSMB2PodTests/ServerE2E"
SDK="$(xcrun --show-sdk-path)"
BUILD="$(mktemp -d /tmp/amsmb2-swift-e2e.XXXXXX)"

USER_NAME="smbtester"
PASS="Passw0rd!"

echo "== building libsmb2 =="
mkdir -p "$BUILD/obj"
for f in "$LSMB"/lib/*.c; do
  clang -c "$f" -o "$BUILD/obj/$(basename "$f" .c).o" \
    -I "$LSMB/include" -I "$LSMB/include/apple" -I "$LSMB/include/smb2" -I "$LSMB/lib" \
    -D_U_='__attribute__((unused))' -DHAVE_CONFIG_H=1 -isysroot "$SDK" -Wno-everything
done
ar rcs "$BUILD/libsmb2.a" "$BUILD"/obj/*.o

echo "== building server_bin =="
clang -fobjc-arc -o "$BUILD/server_bin" \
  "$E2E/server_main.m" "$OBJC/AMSMB2Server.m" "$OBJC/SMB2Helpers.m" "$BUILD/libsmb2.a" \
  -I "$LSMB/include" -I "$OBJC" -DHAVE_STDINT_H=1 -DHAVE_TIME_H=1 \
  -isysroot "$SDK" -framework Foundation -framework Security

# Pre-build the Swift test bundle once so per-posture runs are quick.
echo "== building Swift test bundle =="
( cd "$REPO" && swift build --build-tests >/dev/null )

SRVPID=""
start_server() { # $1=root $2=port $3=full $4=sign [$5=user $6=pass $7=enc]
  "$BUILD/server_bin" "$@" > "$BUILD/server.log" 2>&1 &
  SRVPID=$!
  for _ in $(seq 1 50); do grep -q "SERVER UP" "$BUILD/server.log" 2>/dev/null && break; sleep 0.1; done
}
stop_server() { [ -n "$SRVPID" ] && kill "$SRVPID" 2>/dev/null || true; SRVPID=""; }
trap 'stop_server; rm -rf "$BUILD"' EXIT

run_posture() { # $1=label  rest: env for swift test
  local label="$1"; shift
  echo ""
  echo "======================================================================"
  echo "==  Swift SMB2ManagerTests  --  posture: $label"
  echo "======================================================================"
  ( cd "$REPO" && env "$@" swift test --skip-build --filter SMB2ManagerTests )
}

PORT=8455

# ---- 1. plain (anonymous) --------------------------------------------------
ROOT="$(mktemp -d /tmp/amsmb2-share.XXXXXX)"; echo seed > "$ROOT/readme.txt"
start_server "$ROOT" "$PORT" 1 0
run_posture "plain (anonymous, unsigned, unencrypted)" \
  SMB_SERVER="smb://127.0.0.1:$PORT" SMB_SHARE=Share SMB_ENCRYPTED=0
stop_server; rm -rf "$ROOT"

# ---- 2. signed (authenticated + signing required) --------------------------
PORT=$((PORT + 1))
ROOT="$(mktemp -d /tmp/amsmb2-share.XXXXXX)"; echo seed > "$ROOT/readme.txt"
start_server "$ROOT" "$PORT" 1 1 "$USER_NAME" "$PASS"
run_posture "signed (auth + SMB signing)" \
  SMB_SERVER="smb://127.0.0.1:$PORT" SMB_SHARE=Share \
  SMB_USER="$USER_NAME" SMB_PASSWORD="$PASS" SMB_ENCRYPTED=0
stop_server; rm -rf "$ROOT"

# ---- 3. encrypted (authenticated + SMB3 seal 3.1.1) ------------------------
PORT=$((PORT + 1))
ROOT="$(mktemp -d /tmp/amsmb2-share.XXXXXX)"; echo seed > "$ROOT/readme.txt"
start_server "$ROOT" "$PORT" 1 1 "$USER_NAME" "$PASS" 1
run_posture "encrypted (auth + SMB3 seal, AES-128-CCM)" \
  SMB_SERVER="smb://127.0.0.1:$PORT" SMB_SHARE=Share \
  SMB_USER="$USER_NAME" SMB_PASSWORD="$PASS" SMB_ENCRYPTED=1
stop_server; rm -rf "$ROOT"

echo ""
echo "==== all postures passed (plain + signed + encrypted) ===="
