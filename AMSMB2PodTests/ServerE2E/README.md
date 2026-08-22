# AMSMB2 SMB Server — End-to-End Tests

Integration tests for `AMSMB2Server` (the ObjC SMB server wrapper). They run the
server as one process and drive it through a real libsmb2 **client** in another.

## Why two processes?

libsmb2 keeps a **global** list of active contexts, and the server's serve loop
services every context in it. If a client context lived in the same process, the
server loop would service (and corrupt) the client's stream — a plain in-process
client+server fails with *"Failed to decode smb2 header"*. So these tests use two
separate binaries. (This is also why the iOS `PodTestsTests/AMSMB2ServerTests.m`
target only covers lifecycle/bind — iOS can't spawn a second process.)

## Run

```bash
./run.sh            # default port 8445
./run.sh 8600       # custom port
```

`run.sh` builds a static libsmb2 from `Dependencies/libsmb2`, builds the server
(`server_main.m` + `AMSMB2Server.m` + `SMB2Helpers.m`) and the clients, starts
the server over a temp directory, and runs:

1. **`client_main.c`** — a quick smoke test (connect / list / write / read /
   rename / mkdir / delete).
2. **`client_tests.c`** — the comprehensive suite (30 cases). Exit code 0 iff all
   pass.

## Coverage (30 cases)

| Area | Tests |
|------|-------|
| Directory listing | empty dir, dir with files, dir with subdirs, mixed types, 50-file listing |
| File I/O (upload/download) | small, 1 MB round-trip, write-at-offset, append, overwrite-truncates, read-past-EOF, empty file |
| Stat | file size, directory type, missing file fails |
| Rename / move | rename file, content preserved, move into subdir, rename dir with contents, rename over existing |
| Delete | file, empty dir, recursive tree, open-missing fails |
| Folder creation | mkdir, deep nested mkdir |
| Special names | spaces, Unicode/umlaut (café_Ünïcödé_日本語), symbols `-_.()+[]#` |
| Copy | read-source + write-destination, verify content, source retained |

## Files

- `server_main.m` — a filesystem-backed `AMSMB2ServerDelegate` over a temp dir.
  Args: `<root> <port> [fullControl=1] [signing=1]`.
- `client_main.c` — smoke test.
- `client_tests.c` — the 30-case suite.
- `run.sh` — build + orchestrate.

## Manual check against Apple's client

```bash
# terminal 1
clang -fobjc-arc -o /tmp/srv server_main.m ../../AMSMB2ObjC/AMSMB2Server.m \
  ../../AMSMB2ObjC/SMB2Helpers.m /tmp/libsmb2.a \
  -I ../../Dependencies/libsmb2/include -I ../../AMSMB2ObjC \
  -isysroot "$(xcrun --show-sdk-path)" -framework Foundation -framework Security
/tmp/srv "$(mktemp -d)" 4455 1 1

# terminal 2
mount_smbfs -N //guest@127.0.0.1:4455/Share /tmp/mnt
ls -la /tmp/mnt ; df -h /tmp/mnt
```
