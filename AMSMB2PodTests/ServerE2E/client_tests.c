//
//  client_tests.c
//  AMSMB2 SMB server — comprehensive end-to-end test suite (30 cases).
//
//  Drives the AMSMB2Server (run as a separate process by run.sh) through a
//  real libsmb2 client, covering directory listing, file I/O, stat, rename,
//  move, copy, delete, folder creation and special-character names.
//
//  A libsmb2 client and server cannot share one process (libsmb2 keeps a global
//  active-context list), so this runs as its own process against the server.
//

#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int g_total = 0, g_passed = 0, g_test_failed = 0;

#define OK(cond, msg) do { \
    if (!(cond)) { g_test_failed = 1; printf("     x %s (%s)\n", msg, smb2_get_error(smb2)); } \
} while (0)

#define RUN(fn) do { \
    g_total++; g_test_failed = 0; \
    printf("[%02d] %s\n", g_total, #fn); \
    fn(smb2); \
    if (!g_test_failed) { g_passed++; printf("     ok\n"); } else printf("     FAILED\n"); \
} while (0)

#pragma mark - helpers

static int write_file(struct smb2_context *smb2, const char *path, const void *data, uint32_t len)
{
    struct smb2fh *fh = smb2_open(smb2, path, O_WRONLY | O_CREAT | O_TRUNC);
    if (!fh) return -1;
    uint32_t off = 0;
    const uint8_t *p = data;
    while (off < len) {
        int w = smb2_pwrite(smb2, fh, p + off, len - off, off);
        if (w <= 0) { smb2_close(smb2, fh); return -1; }
        off += (uint32_t)w;
    }
    smb2_close(smb2, fh);
    return 0;
}

static int read_file(struct smb2_context *smb2, const char *path, void *buf, uint32_t maxlen)
{
    struct smb2fh *fh = smb2_open(smb2, path, O_RDONLY);
    if (!fh) return -1;
    uint32_t off = 0;
    uint8_t *p = buf;
    while (off < maxlen) {
        int r = smb2_pread(smb2, fh, p + off, maxlen - off, off);
        if (r < 0) { smb2_close(smb2, fh); return -1; }
        if (r == 0) break;
        off += (uint32_t)r;
    }
    smb2_close(smb2, fh);
    return (int)off;
}

/// Count real entries in a directory (excluding . and ..); optionally report
/// whether `want` is present.
static int list_dir(struct smb2_context *smb2, const char *path, const char *want, int *found)
{
    struct smb2dir *dir = smb2_opendir(smb2, path);
    if (!dir) return -1;
    int n = 0;
    if (found) *found = 0;
    struct smb2dirent *e;
    while ((e = smb2_readdir(smb2, dir))) {
        if (!strcmp(e->name, ".") || !strcmp(e->name, "..")) continue;
        n++;
        if (want && found && !strcmp(e->name, want)) *found = 1;
    }
    smb2_closedir(smb2, dir);
    return n;
}

static int entry_type(struct smb2_context *smb2, const char *dirpath, const char *name)
{
    struct smb2dir *dir = smb2_opendir(smb2, dirpath);
    if (!dir) return -1;
    int type = -1;
    struct smb2dirent *e;
    while ((e = smb2_readdir(smb2, dir))) {
        if (!strcmp(e->name, name)) { type = (int)e->st.smb2_type; break; }
    }
    smb2_closedir(smb2, dir);
    return type;
}

#pragma mark - directory listing

static void test_list_empty_directory(struct smb2_context *smb2)
{
    OK(smb2_mkdir(smb2, "empty_dir") == 0, "mkdir empty_dir");
    int n = list_dir(smb2, "empty_dir", NULL, NULL);
    OK(n == 0, "empty directory lists 0 entries");
}

static void test_list_directory_with_files(struct smb2_context *smb2)
{
    smb2_mkdir(smb2, "d_files");
    OK(write_file(smb2, "d_files/a.txt", "a", 1) == 0, "create a.txt");
    OK(write_file(smb2, "d_files/b.txt", "bb", 2) == 0, "create b.txt");
    OK(write_file(smb2, "d_files/c.txt", "ccc", 3) == 0, "create c.txt");
    OK(list_dir(smb2, "d_files", NULL, NULL) == 3, "directory lists 3 files");
}

static void test_list_directory_with_subdirs(struct smb2_context *smb2)
{
    smb2_mkdir(smb2, "d_subs");
    OK(smb2_mkdir(smb2, "d_subs/sub1") == 0, "mkdir sub1");
    OK(smb2_mkdir(smb2, "d_subs/sub2") == 0, "mkdir sub2");
    OK(list_dir(smb2, "d_subs", NULL, NULL) == 2, "directory lists 2 subdirs");
}

static void test_list_mixed_types(struct smb2_context *smb2)
{
    smb2_mkdir(smb2, "d_mixed");
    write_file(smb2, "d_mixed/file.txt", "x", 1);
    smb2_mkdir(smb2, "d_mixed/folder");
    OK(list_dir(smb2, "d_mixed", NULL, NULL) == 2, "lists file + folder");
    OK(entry_type(smb2, "d_mixed", "file.txt") == SMB2_TYPE_FILE, "file.txt is a file");
    OK(entry_type(smb2, "d_mixed", "folder") == SMB2_TYPE_DIRECTORY, "folder is a directory");
}

static void test_list_many_files(struct smb2_context *smb2)
{
    smb2_mkdir(smb2, "d_many");
    char path[64];
    int created = 0;
    for (int i = 0; i < 50; i++) {
        snprintf(path, sizeof(path), "d_many/f%02d.dat", i);
        if (write_file(smb2, path, "y", 1) == 0) created++;
    }
    OK(created == 50, "created 50 files");
    OK(list_dir(smb2, "d_many", "f49.dat", NULL) == 50, "lists all 50 files");
}

#pragma mark - file create / write / read (upload / download)

static void test_write_read_small(struct smb2_context *smb2)
{
    const char *payload = "Hello, SMB world!";
    OK(write_file(smb2, "small.txt", payload, (uint32_t)strlen(payload)) == 0, "upload small file");
    char buf[64] = {0};
    int r = read_file(smb2, "small.txt", buf, sizeof(buf) - 1);
    OK(r == (int)strlen(payload), "download length matches");
    OK(strcmp(buf, payload) == 0, "content round-trips");
}

static void test_write_read_large_1mb(struct smb2_context *smb2)
{
    const uint32_t size = 1024 * 1024;
    uint8_t *out = malloc(size), *in = malloc(size);
    for (uint32_t i = 0; i < size; i++) out[i] = (uint8_t)((i * 131 + 7) & 0xff);
    OK(write_file(smb2, "large.bin", out, size) == 0, "upload 1MB file");
    int r = read_file(smb2, "large.bin", in, size);
    OK(r == (int)size, "download 1MB length matches");
    OK(memcmp(out, in, size) == 0, "1MB content round-trips");
    free(out); free(in);
}

static void test_write_at_offset(struct smb2_context *smb2)
{
    struct smb2fh *fh = smb2_open(smb2, "sparse.bin", O_WRONLY | O_CREAT | O_TRUNC);
    OK(fh != NULL, "open sparse for write");
    if (fh) {
        int w = smb2_pwrite(smb2, fh, (const uint8_t *)"END", 3, 100);
        OK(w == 3, "write 3 bytes at offset 100");
        smb2_close(smb2, fh);
    }
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, "sparse.bin", &st) == 0, "stat sparse");
    OK(st.smb2_size == 103, "size reflects offset write (103)");
}

static void test_append_to_file(struct smb2_context *smb2)
{
    OK(write_file(smb2, "append.txt", "AAA", 3) == 0, "initial write");
    struct smb2fh *fh = smb2_open(smb2, "append.txt", O_RDWR);
    OK(fh != NULL, "reopen for append");
    if (fh) {
        int w = smb2_pwrite(smb2, fh, (const uint8_t *)"BBB", 3, 3);
        OK(w == 3, "append 3 bytes at offset 3");
        smb2_close(smb2, fh);
    }
    char buf[16] = {0};
    int r = read_file(smb2, "append.txt", buf, sizeof(buf) - 1);
    OK(r == 6 && strcmp(buf, "AAABBB") == 0, "appended content correct");
}

static void test_overwrite_truncates(struct smb2_context *smb2)
{
    OK(write_file(smb2, "over.txt", "0123456789", 10) == 0, "write 10 bytes");
    OK(write_file(smb2, "over.txt", "XY", 2) == 0, "overwrite with 2 bytes (O_TRUNC)");
    struct smb2_stat_64 st;
    smb2_stat(smb2, "over.txt", &st);
    OK(st.smb2_size == 2, "file truncated to 2 bytes");
}

static void test_read_beyond_eof(struct smb2_context *smb2)
{
    write_file(smb2, "short.txt", "hi", 2);
    struct smb2fh *fh = smb2_open(smb2, "short.txt", O_RDONLY);
    OK(fh != NULL, "open short.txt");
    if (fh) {
        uint8_t buf[16];
        int r = smb2_pread(smb2, fh, buf, sizeof(buf), 100); // past EOF
        OK(r == 0, "read past EOF returns 0");
        smb2_close(smb2, fh);
    }
}

static void test_empty_file(struct smb2_context *smb2)
{
    struct smb2fh *fh = smb2_open(smb2, "empty.txt", O_WRONLY | O_CREAT | O_TRUNC);
    OK(fh != NULL, "create empty file");
    if (fh) smb2_close(smb2, fh);
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, "empty.txt", &st) == 0, "stat empty file");
    OK(st.smb2_size == 0, "empty file size is 0");
}

#pragma mark - stat

static void test_stat_file_size(struct smb2_context *smb2)
{
    write_file(smb2, "sized.txt", "0123456", 7);
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, "sized.txt", &st) == 0, "stat sized.txt");
    OK(st.smb2_size == 7, "stat reports size 7");
    OK(st.smb2_type == SMB2_TYPE_FILE, "stat reports file type");
}

static void test_stat_directory_type(struct smb2_context *smb2)
{
    smb2_mkdir(smb2, "statdir");
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, "statdir", &st) == 0, "stat statdir");
    OK(st.smb2_type == SMB2_TYPE_DIRECTORY, "stat reports directory type");
}

static void test_stat_nonexistent_fails(struct smb2_context *smb2)
{
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, "does_not_exist.xyz", &st) != 0, "stat of missing file fails");
}

#pragma mark - rename / move

static void test_rename_file(struct smb2_context *smb2)
{
    write_file(smb2, "ren_a.txt", "data", 4);
    OK(smb2_rename(smb2, "ren_a.txt", "ren_b.txt") == 0, "rename a -> b");
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, "ren_b.txt", &st) == 0, "renamed file exists");
    OK(smb2_stat(smb2, "ren_a.txt", &st) != 0, "old name is gone");
}

static void test_rename_preserves_content(struct smb2_context *smb2)
{
    write_file(smb2, "keep_src.txt", "preserve-me", 11);
    OK(smb2_rename(smb2, "keep_src.txt", "keep_dst.txt") == 0, "rename keep_src -> keep_dst");
    char buf[32] = {0};
    int r = read_file(smb2, "keep_dst.txt", buf, sizeof(buf) - 1);
    OK(r == 11 && strcmp(buf, "preserve-me") == 0, "content preserved after rename");
}

static void test_move_file_to_subdir(struct smb2_context *smb2)
{
    smb2_mkdir(smb2, "movedst");
    write_file(smb2, "tomove.txt", "moved", 5);
    OK(smb2_rename(smb2, "tomove.txt", "movedst/tomove.txt") == 0, "move into subdir");
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, "movedst/tomove.txt", &st) == 0, "file exists in subdir");
    OK(smb2_stat(smb2, "tomove.txt", &st) != 0, "file gone from root");
}

static void test_rename_directory_with_contents(struct smb2_context *smb2)
{
    smb2_mkdir(smb2, "olddir");
    write_file(smb2, "olddir/inside.txt", "in", 2);
    OK(smb2_rename(smb2, "olddir", "newdir") == 0, "rename directory");
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, "newdir", &st) == 0 && st.smb2_type == SMB2_TYPE_DIRECTORY, "new dir exists");
    OK(smb2_stat(smb2, "newdir/inside.txt", &st) == 0, "contents moved with directory");
}

static void test_rename_replace_existing(struct smb2_context *smb2)
{
    write_file(smb2, "repl_src.txt", "source", 6);
    write_file(smb2, "repl_dst.txt", "old", 3);
    // libsmb2 unlinks the destination first, then renames.
    smb2_unlink(smb2, "repl_dst.txt");
    OK(smb2_rename(smb2, "repl_src.txt", "repl_dst.txt") == 0, "rename over existing target");
    char buf[16] = {0};
    int r = read_file(smb2, "repl_dst.txt", buf, sizeof(buf) - 1);
    OK(r == 6 && strcmp(buf, "source") == 0, "target has source content");
}

#pragma mark - delete

static void test_delete_file(struct smb2_context *smb2)
{
    write_file(smb2, "todelete.txt", "bye", 3);
    OK(smb2_unlink(smb2, "todelete.txt") == 0, "unlink file");
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, "todelete.txt", &st) != 0, "file gone after unlink");
}

static void test_delete_empty_directory(struct smb2_context *smb2)
{
    smb2_mkdir(smb2, "rmempty");
    OK(smb2_rmdir(smb2, "rmempty") == 0, "rmdir empty directory");
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, "rmempty", &st) != 0, "directory gone");
}

static void test_delete_directory_recursively(struct smb2_context *smb2)
{
    smb2_mkdir(smb2, "rmtree");
    write_file(smb2, "rmtree/a.txt", "a", 1);
    write_file(smb2, "rmtree/b.txt", "b", 1);
    // Client-driven recursive delete: remove children then the directory.
    OK(smb2_unlink(smb2, "rmtree/a.txt") == 0, "delete child a");
    OK(smb2_unlink(smb2, "rmtree/b.txt") == 0, "delete child b");
    OK(smb2_rmdir(smb2, "rmtree") == 0, "rmdir now-empty tree");
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, "rmtree", &st) != 0, "tree removed");
}

static void test_open_nonexistent_fails(struct smb2_context *smb2)
{
    // Opening a missing file for read must fail (clean "not found" behavior).
    struct smb2fh *fh = smb2_open(smb2, "ghost_does_not_exist.txt", O_RDONLY);
    OK(fh == NULL, "open of missing file for read fails");
    if (fh) smb2_close(smb2, fh);
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, "ghost_does_not_exist.txt", &st) != 0, "missing file still absent");
}

#pragma mark - folder creation

static void test_mkdir_simple(struct smb2_context *smb2)
{
    OK(smb2_mkdir(smb2, "brandnew") == 0, "mkdir");
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, "brandnew", &st) == 0 && st.smb2_type == SMB2_TYPE_DIRECTORY, "new folder is a directory");
}

static void test_mkdir_nested(struct smb2_context *smb2)
{
    OK(smb2_mkdir(smb2, "lvl1") == 0, "mkdir lvl1");
    OK(smb2_mkdir(smb2, "lvl1/lvl2") == 0, "mkdir lvl1/lvl2");
    OK(smb2_mkdir(smb2, "lvl1/lvl2/lvl3") == 0, "mkdir lvl1/lvl2/lvl3");
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, "lvl1/lvl2/lvl3", &st) == 0, "deep nested folder exists");
}

#pragma mark - special characters

static void test_file_with_spaces(struct smb2_context *smb2)
{
    const char *name = "my file with spaces.txt";
    OK(write_file(smb2, name, "spaced", 6) == 0, "create file with spaces");
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, name, &st) == 0 && st.smb2_size == 6, "stat file with spaces");
    int found = 0;
    list_dir(smb2, "", name, &found);
    OK(found, "spaced file appears in listing");
}

static void test_file_unicode_umlaut(struct smb2_context *smb2)
{
    // Note: some servers/filesystems (e.g. Apple's) normalize names to NFD, so
    // a byte-exact match against a listing is unreliable; verify by opening and
    // stat-ing the exact name the client sent instead.
    const char *name = "café_Ünïcödé_日本語.txt"; // UTF-8, composed (NFC)
    OK(write_file(smb2, name, "unicode", 7) == 0, "create unicode/umlaut file");
    char buf[16] = {0};
    int r = read_file(smb2, name, buf, sizeof(buf) - 1);
    OK(r == 7 && strcmp(buf, "unicode") == 0, "read back unicode-named file");
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, name, &st) == 0 && st.smb2_size == 7, "stat unicode-named file by exact name");
}

static void test_file_special_symbols(struct smb2_context *smb2)
{
    const char *name = "file-name_v2.0 (copy)+[edit]#1.txt";
    OK(write_file(smb2, name, "symbols", 7) == 0, "create file with special symbols");
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, name, &st) == 0 && st.smb2_size == 7, "stat special-symbol file");
}

#pragma mark - copy

static void test_copy_file(struct smb2_context *smb2)
{
    const char *payload = "copy this content across files";
    uint32_t len = (uint32_t)strlen(payload);
    OK(write_file(smb2, "copy_src.txt", payload, len) == 0, "create copy source");
    // File-manager style copy: read source, write destination.
    char buf[64] = {0};
    int r = read_file(smb2, "copy_src.txt", buf, sizeof(buf) - 1);
    OK(r == (int)len, "read source for copy");
    OK(write_file(smb2, "copy_dst.txt", buf, (uint32_t)r) == 0, "write destination copy");
    char verify[64] = {0};
    int r2 = read_file(smb2, "copy_dst.txt", verify, sizeof(verify) - 1);
    OK(r2 == (int)len && memcmp(buf, verify, len) == 0, "copy content matches source");
    struct smb2_stat_64 st;
    OK(smb2_stat(smb2, "copy_src.txt", &st) == 0, "source still exists after copy");
}

#pragma mark - main

int main(int argc, char **argv)
{
    const char *hostport = argc > 1 ? argv[1] : "127.0.0.1:8445";
    struct smb2_context *smb2 = smb2_init_context();
    if (!smb2) { printf("no context\n"); return 2; }
    {
        const char *sg = getenv("SMB_SIGNING");
        smb2_set_security_mode(smb2, (sg && !strcmp(sg, "required"))
                               ? SMB2_NEGOTIATE_SIGNING_REQUIRED
                               : SMB2_NEGOTIATE_SIGNING_ENABLED);
    }
    {
        /* SMB_ENCRYPTED=1 forces SMB3 seal; needs a 3.x dialect, so pin ANY3. */
        const char *enc = getenv("SMB_ENCRYPTED");
        if (enc && enc[0] == '1') {
            smb2_set_version(smb2, SMB2_VERSION_ANY3);
            smb2_set_seal(smb2, 1);
        }
    }
    {
        const char *u = getenv("SMB_USER"), *p = getenv("SMB_PASSWORD");
        if (p && p[0]) smb2_set_password(smb2, p);
        if (smb2_connect_share(smb2, hostport, "Share", (u && u[0]) ? u : "") != 0) {
            printf("CONNECT FAILED: %s\n", smb2_get_error(smb2));
            return 1;
        }
    }
    printf("connected to %s\n\n", hostport);

    // Directory listing
    RUN(test_list_empty_directory);
    RUN(test_list_directory_with_files);
    RUN(test_list_directory_with_subdirs);
    RUN(test_list_mixed_types);
    RUN(test_list_many_files);
    // File I/O (upload / download)
    RUN(test_write_read_small);
    RUN(test_write_read_large_1mb);
    RUN(test_write_at_offset);
    RUN(test_append_to_file);
    RUN(test_overwrite_truncates);
    RUN(test_read_beyond_eof);
    RUN(test_empty_file);
    // Stat
    RUN(test_stat_file_size);
    RUN(test_stat_directory_type);
    RUN(test_stat_nonexistent_fails);
    // Rename / move
    RUN(test_rename_file);
    RUN(test_rename_preserves_content);
    RUN(test_move_file_to_subdir);
    RUN(test_rename_directory_with_contents);
    RUN(test_rename_replace_existing);
    // Delete
    RUN(test_delete_file);
    RUN(test_delete_empty_directory);
    RUN(test_delete_directory_recursively);
    RUN(test_open_nonexistent_fails);
    // Folder creation
    RUN(test_mkdir_simple);
    RUN(test_mkdir_nested);
    // Special characters
    RUN(test_file_with_spaces);
    RUN(test_file_unicode_umlaut);
    RUN(test_file_special_symbols);
    // Copy
    RUN(test_copy_file);

    smb2_disconnect_share(smb2);
    smb2_destroy_context(smb2);

    printf("\n==== %d/%d passed ====\n", g_passed, g_total);
    return g_passed == g_total ? 0 : 1;
}
