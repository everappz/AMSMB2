/*
 * Share-enumeration E2E test for the AMSMB2 ObjC SMB server.
 *
 * Drives the server's srvsvc named-pipe responder exactly the way macOS Finder
 * does: connect to IPC$, open the `srvsvc` pipe, BIND, and call NetrShareEnum
 * (opnum 0x0f) over FSCTL_PIPE_TRANSCEIVE via libsmb2's smb2_share_enum_sync().
 * Verifies the reply lists our disk share plus IPC$.
 *
 * Exit code 0 iff every assertion passes.
 */
#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>
#include <smb2/libsmb2-share-enum.h>

int main(int argc, char **argv)
{
    const char *hostport = argc > 1 ? argv[1] : "127.0.0.1:8445";
    int failures = 0;

    struct smb2_context *smb2 = smb2_init_context();
    if (!smb2) { printf("no context\n"); return 2; }
    smb2_set_security_mode(smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);

    printf("[connect IPC$] %s\n", hostport);
    if (smb2_connect_share(smb2, hostport, "IPC$", "")) {
        printf("  FAIL: connect IPC$ (%s)\n", smb2_get_error(smb2));
        smb2_destroy_context(smb2);
        return 1;
    }
    printf("  PASS: connect IPC$\n");

    printf("[NetrShareEnum level 1]\n");
    struct srvsvc_NetrShareEnum_rep *rep = smb2_share_enum_sync(smb2, SHARE_INFO_1);
    if (!rep) {
        printf("  FAIL: share_enum (%s)\n", smb2_get_error(smb2));
        smb2_disconnect_share(smb2);
        smb2_destroy_context(smb2);
        return 1;
    }

    struct srvsvc_SHARE_INFO_1_CONTAINER *ctr = &rep->ses.ShareEnum.Level1;
    printf("  status=0x%08x EntriesRead=%u total_entries=%u\n",
           rep->status, ctr->EntriesRead, rep->total_entries);

    int sawShare = 0, sawIPC = 0;
    for (uint32_t i = 0; i < ctr->EntriesRead && ctr->share_info_1; i++) {
        const char *nm = ctr->share_info_1[i].netname;
        printf("    [%u] name=\"%s\" type=0x%08x remark=\"%s\"\n",
               i, nm ? nm : "(null)", ctr->share_info_1[i].type,
               ctr->share_info_1[i].remark ? ctr->share_info_1[i].remark : "");
        if (nm && strcmp(nm, "Share") == 0) sawShare = 1;
        if (nm && strcmp(nm, "IPC$") == 0)  sawIPC = 1;
    }

#define CHECK(cond, msg) do { \
    if (cond) { printf("  PASS: %s\n", msg); } \
    else { printf("  FAIL: %s\n", msg); failures++; } \
} while (0)

    CHECK(rep->status == 0, "NetrShareEnum status == 0");
    CHECK(ctr->EntriesRead == 2, "EntriesRead == 2");
    CHECK(rep->total_entries == 2, "total_entries == 2");
    CHECK(sawShare, "share list contains \"Share\" (disk)");
    CHECK(sawIPC, "share list contains \"IPC$\"");

    smb2_free_data(smb2, rep);
    smb2_disconnect_share(smb2);
    smb2_destroy_context(smb2);

    printf(failures ? "\n==== share-enum FAILED (%d) ====\n"
                    : "\n==== share-enum PASSED ====\n", failures);
    return failures ? 1 : 0;
}
