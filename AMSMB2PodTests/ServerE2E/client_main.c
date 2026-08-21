#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  PASS: %s\n", msg); } \
    else { printf("  FAIL: %s (%s)\n", msg, smb2_get_error(smb2)); failures++; } \
} while (0)

int main(int argc, char **argv)
{
    const char *hostport = argc > 1 ? argv[1] : "127.0.0.1:8445";
    struct smb2_context *smb2 = smb2_init_context();
    if (!smb2) { printf("no context\n"); return 2; }

    smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);

    printf("[connect] %s\n", hostport);
    int rc = smb2_connect_share(smb2, hostport, "Share", "");
    if (rc) { printf("  FAIL: connect (%s)\n", smb2_get_error(smb2)); return 1; }
    printf("  PASS: connect\n");

    /* 1. list root (should have . and ..) */
    printf("[list root]\n");
    struct smb2dir *dir = smb2_opendir(smb2, "");
    CHECK(dir != NULL, "opendir root");
    int nEntries = 0, sawReadme = 0;
    if (dir) {
        struct smb2dirent *ent;
        while ((ent = smb2_readdir(smb2, dir))) {
            printf("    entry: %-16s type=%u size=%llu\n", ent->name, ent->st.smb2_type,
                   (unsigned long long)ent->st.smb2_size);
            if (!strcmp(ent->name, "readme.txt")) sawReadme = 1;
            nEntries++;
        }
        smb2_closedir(smb2, dir);
    }
    CHECK(sawReadme, "root lists seeded readme.txt");

    /* 2. create + write */
    printf("[write hello.txt]\n");
    const char *payload = "Hello from AMSMB2 server!";
    uint32_t plen = (uint32_t)strlen(payload);
    struct smb2fh *fh = smb2_open(smb2, "hello.txt", O_WRONLY | O_CREAT | O_TRUNC);
    CHECK(fh != NULL, "open hello.txt for write");
    if (fh) {
        int w = smb2_pwrite(smb2, fh, (const uint8_t *)payload, plen, 0);
        CHECK(w == (int)plen, "pwrite full payload");
        smb2_close(smb2, fh);
    }

    /* 3. read back */
    printf("[read hello.txt]\n");
    fh = smb2_open(smb2, "hello.txt", O_RDONLY);
    CHECK(fh != NULL, "open hello.txt for read");
    if (fh) {
        uint8_t buf[128];
        memset(buf, 0, sizeof(buf));
        int r = smb2_pread(smb2, fh, buf, sizeof(buf) - 1, 0);
        CHECK(r == (int)plen, "pread length matches");
        CHECK(memcmp(buf, payload, plen) == 0, "content round-trips");
        printf("    read back: \"%s\"\n", buf);
        smb2_close(smb2, fh);
    }

    /* 4. stat */
    printf("[stat hello.txt]\n");
    struct smb2_stat_64 st;
    rc = smb2_stat(smb2, "hello.txt", &st);
    CHECK(rc == 0, "stat hello.txt");
    CHECK(st.smb2_size == plen, "stat size matches payload");

    /* 5. rename (SET_INFO — passthrough path) */
    printf("[rename hello.txt -> world.txt]\n");
    rc = smb2_rename(smb2, "hello.txt", "world.txt");
    CHECK(rc == 0, "rename hello.txt -> world.txt");
    rc = smb2_stat(smb2, "world.txt", &st);
    CHECK(rc == 0, "stat world.txt after rename");

    /* 6. mkdir */
    printf("[mkdir subdir]\n");
    rc = smb2_mkdir(smb2, "subdir");
    CHECK(rc == 0, "mkdir subdir");
    rc = smb2_stat(smb2, "subdir", &st);
    CHECK(rc == 0 && st.smb2_type == SMB2_TYPE_DIRECTORY, "subdir is a directory");

    /* 7. re-list, confirm world.txt + subdir present, hello.txt gone */
    printf("[re-list root]\n");
    int sawWorld = 0, sawHello = 0, sawSub = 0;
    dir = smb2_opendir(smb2, "");
    if (dir) {
        struct smb2dirent *ent;
        while ((ent = smb2_readdir(smb2, dir))) {
            if (!strcmp(ent->name, "world.txt")) sawWorld = 1;
            if (!strcmp(ent->name, "hello.txt")) sawHello = 1;
            if (!strcmp(ent->name, "subdir")) sawSub = 1;
        }
        smb2_closedir(smb2, dir);
    }
    CHECK(sawWorld, "world.txt present after rename");
    CHECK(!sawHello, "hello.txt gone after rename");
    CHECK(sawSub, "subdir present after mkdir");

    /* 8. delete */
    printf("[unlink world.txt]\n");
    rc = smb2_unlink(smb2, "world.txt");
    CHECK(rc == 0, "unlink world.txt");
    rc = smb2_stat(smb2, "world.txt", &st);
    CHECK(rc != 0, "world.txt gone after unlink");

    smb2_disconnect_share(smb2);
    smb2_destroy_context(smb2);

    printf("\n==== %s (%d failure%s) ====\n", failures == 0 ? "ALL PASSED" : "FAILURES",
           failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
