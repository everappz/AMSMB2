#!/bin/bash
#
# Build + run the standalone OBJC AMSMB2 client coverage suite against a real server.
#
# Links AMSMB2ObjC/*.m + a locally-built static libsmb2 (from Dependencies/libsmb2) and drives the
# AMSMB2Manager completion-handler API synchronously. Credentials come from the environment; only the
# (non-secret) server address/share are defaulted in the test source.
#
#   SMB_USER=... SMB_PASSWORD=... ./run.sh
#   SMB_SERVER=smb://host SMB_SHARE=Public SMB_USER=... SMB_PASSWORD=... ./run.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
LSMB="$REPO/Dependencies/libsmb2"
OBJC="$REPO/AMSMB2ObjC"
SDK="$(xcrun --show-sdk-path)"
BUILD="$(mktemp -d /tmp/amsmb2-client.XXXXXX)"
trap 'rm -rf "$BUILD"' EXIT

echo "== building libsmb2 =="
mkdir -p "$BUILD/obj"
for f in "$LSMB"/lib/*.c; do
  clang -c "$f" -o "$BUILD/obj/$(basename "$f" .c).o" \
    -I "$LSMB/include" -I "$LSMB/include/apple" -I "$LSMB/include/smb2" -I "$LSMB/lib" \
    -D_U_='__attribute__((unused))' -DHAVE_CONFIG_H=1 -isysroot "$SDK" -Wno-everything
done
ar rcs "$BUILD/libsmb2.a" "$BUILD"/obj/*.o

echo "== building objc client + coverage harness =="
clang -fobjc-arc -o "$BUILD/client_coverage" \
  "$HERE/client_coverage.m" \
  "$OBJC/AMSMB2Manager.m" "$OBJC/SMB2Client.m" "$OBJC/SMB2FileHandle.m" "$OBJC/SMB2Directory.m" "$OBJC/SMB2Helpers.m" \
  "$BUILD/libsmb2.a" \
  -I "$LSMB/include" -I "$OBJC" -DHAVE_STDINT_H=1 -DHAVE_TIME_H=1 \
  -isysroot "$SDK" -framework Foundation -framework Security

echo "== running =="
"$BUILD/client_coverage"
