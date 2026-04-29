// TEST.c
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

static int total_checks;
static int failed_checks;
static int skipped_checks;
static int req_access_seen;
static int req_create_seen;
static int req_delete_or_rename_seen;
static int req_listdir_seen;

static void step_note(const char *id, const char *tests, const char *expects)
{
    printf("STEP %s\n", id);
    printf("  TESTS : %s\n", tests);
    printf("  EXPECT: %s\n", expects);
}

static void report_ok(const char *op, long ret)
{
    printf("CHECK PASS %s ret=%ld\n", op, ret);
}

static void report_fail(const char *op, long ret)
{
    printf("CHECK FAIL %s ret=%ld errno=%d (%s)\n", op, ret, errno, strerror(errno));
}

static void report_skip(const char *op, long ret)
{
    printf("CHECK SKIP %s ret=%ld errno=%d (%s)\n", op, ret, errno, strerror(errno));
}

static void check_ret(const char *op, int ret, int allow_eexist)
{
    total_checks++;
    if (ret == 0 || (allow_eexist && errno == EEXIST)) {
        report_ok(op, ret);
        return;
    }
    failed_checks++;
    report_fail(op, ret);
}

static void check_fd(const char *op, int fd)
{
    total_checks++;
    if (fd >= 0) {
        report_ok(op, fd);
        return;
    }
    failed_checks++;
    report_fail(op, fd);
}

static void check_sz(const char *op, ssize_t ret, ssize_t expected)
{
    total_checks++;
    if (ret == expected) {
        report_ok(op, ret);
        return;
    }
    failed_checks++;
    if (ret < 0) {
        report_fail(op, ret);
    } else {
        printf("CHECK FAIL %s ret=%zd expected=%zd\n", op, ret, expected);
    }
}

static void check_ret_skip_errno(const char *op, int ret, int skip_errno)
{
    total_checks++;
    if (ret == 0) {
        report_ok(op, ret);
        return;
    }
    if (errno == skip_errno) {
        skipped_checks++;
        report_skip(op, ret);
        return;
    }
    failed_checks++;
    report_fail(op, ret);
}

int main(void) {
    step_note("INIT", "Set process name for monitor filter", "proc=tst_TEST, syscall=prctl visible");
    check_ret("prctl(PR_SET_NAME)", prctl(PR_SET_NAME, "tst_TEST", 0, 0, 0), 0);

    printf("CASE_SETUP START\n");
    step_note("SETUP-1", "Create and enter working directory", "syscalls mkdir/openat/chdir");
    umask(022);
    check_ret("mkdir tst_dir", mkdir("tst_dir", 0755), 1);

    int dfd = open("tst_dir", O_RDONLY | O_DIRECTORY);
    check_fd("open tst_dir", dfd);

    check_ret("chdir tst_dir", chdir("tst_dir"), 0);
    printf("CASE_SETUP END\n");

    printf("CASE_CREATE START\n");
    step_note("CREATE-1", "Create file and attempt hardlinks", "syscalls creat/link/linkat with PASS or SKIP(EPERM)");
    int fd = creat("a.txt", 0640);
    req_create_seen = 1;
    check_fd("creat a.txt", fd);
    if (fd >= 0) {
        check_sz("write a.txt", write(fd, "hello\n", 6), 6);
        check_ret("close a.txt", close(fd), 0);
    }
    check_ret_skip_errno("link a.txt->a.hard", link("a.txt", "a.hard"), EPERM);
    check_ret_skip_errno("linkat a.txt->a.hard2", linkat(AT_FDCWD, "a.txt", AT_FDCWD, "a.hard2", 0), EPERM);
    printf("CASE_CREATE END\n");

    printf("CASE_ACCESS START\n");
    step_note("ACCESS-1", "Check file access rights", "syscalls access/faccessat/faccessat2");
    req_access_seen = 1;
    check_ret("access F_OK a.txt", access("a.txt", F_OK), 0);
    check_ret("access R_OK a.txt", access("a.txt", R_OK), 0);
    check_ret("faccessat R_OK a.txt", faccessat(AT_FDCWD, "a.txt", R_OK, 0), 0);
#ifdef SYS_faccessat2
    check_ret("faccessat2 R_OK a.txt", syscall(SYS_faccessat2, AT_FDCWD, "a.txt", R_OK, 0), 0);
#endif
    step_note("ACCESS-2", "Mutate metadata through path and fd", "syscalls chmod/fchmod/chown/fchown");
    check_ret("chmod a.txt", chmod("a.txt", 0600), 0);
    fd = open("a.txt", O_RDONLY);
    check_fd("open a.txt O_RDONLY", fd);
    if (fd >= 0) {
        check_ret("fchmod a.txt", fchmod(fd, 0644), 0);
        check_ret("fchown a.txt", fchown(fd, getuid(), getgid()), 0);
        check_ret("close fd a.txt", close(fd), 0);
    }
    check_ret("chown a.txt", chown("a.txt", getuid(), getgid()), 0);
    printf("CASE_ACCESS END\n");

    printf("CASE_RENAME START\n");
    step_note("RENAME-1", "Rename via rename/renameat/renameat2", "syscalls rename/renameat/renameat2, renameat2 may SKIP(EINVAL)");
    req_delete_or_rename_seen = 1;
    check_ret("rename a.txt->a_renamed.txt", rename("a.txt", "a_renamed.txt"), 0);
    check_ret("renameat a_renamed.txt->a.txt", renameat(AT_FDCWD, "a_renamed.txt", AT_FDCWD, "a.txt"), 0);
#ifdef SYS_renameat2
    check_ret_skip_errno("renameat2 a.txt->a_renamed.txt", syscall(SYS_renameat2, AT_FDCWD, "a.txt", AT_FDCWD, "a_renamed.txt", 1), EINVAL);
    check_ret_skip_errno("rename back a_renamed.txt->a.txt", rename("a_renamed.txt", "a.txt"), ENOENT);
#endif
    printf("CASE_RENAME END\n");

    printf("CASE_XATTR START\n");
    step_note("XATTR-1", "Symlink and xattr operations", "syscalls symlink/setxattr/getxattr, may SKIP by policy/fs");
    check_ret_skip_errno("symlink a.txt->a.link", symlink("a.txt", "a.link"), EPERM);

    const char *val = "value";
    check_ret_skip_errno("setxattr user.demo", setxattr("a.txt", "user.demo", val, strlen(val), 0), EOPNOTSUPP);
    char buf[64];
    total_checks++;
    if (getxattr("a.txt", "user.demo", buf, sizeof(buf)) >= 0) {
        report_ok("getxattr user.demo", 0);
    } else if (errno == EOPNOTSUPP) {
        skipped_checks++;
        report_skip("getxattr user.demo", -1);
    } else {
        failed_checks++;
        report_fail("getxattr user.demo", -1);
    }
    printf("CASE_XATTR END\n");

    printf("CASE_LISTDIR START\n");
    step_note("LISTDIR-1", "Read directory entries", "syscalls openat/getdents64/close");
    req_listdir_seen = 1;
    DIR *d = opendir(".");
    total_checks++;
    if (d != NULL) {
        report_ok("opendir .", 0);
        while (readdir(d)) {}
        closedir(d);
    } else {
        failed_checks++;
        report_fail("opendir .", -1);
    }
    int dirfd = open(".", O_RDONLY | O_DIRECTORY);
    check_fd("open . O_DIRECTORY", dirfd);
    char dents[4096];
#ifdef SYS_getdents64
    if (dirfd >= 0) {
        total_checks++;
        if (syscall(SYS_getdents64, dirfd, dents, sizeof(dents)) >= 0) {
            report_ok("getdents64", 0);
        } else {
            failed_checks++;
            report_fail("getdents64", -1);
        }
    }
#endif
    if (dirfd >= 0) {
        check_ret("close dirfd", close(dirfd), 0);
    }
    printf("CASE_LISTDIR END\n");

    printf("CASE_DELETE START\n");
    step_note("DELETE-1", "Delete created names", "syscalls unlink/unlinkat, ENOENT treated as SKIP");
    req_delete_or_rename_seen = 1;
    check_ret_skip_errno("unlink a.link", unlink("a.link"), ENOENT);
    check_ret_skip_errno("unlink a.hard", unlink("a.hard"), ENOENT);
    check_ret_skip_errno("unlinkat a.hard2", unlinkat(AT_FDCWD, "a.hard2", 0), ENOENT);
    check_ret("unlink a.txt", unlink("a.txt"), 0);
    printf("CASE_DELETE END\n");

    printf("CASE_CLEANUP START\n");
    step_note("CLEANUP-1", "Return back and remove test directory", "syscalls chdir/fchdir/close/rmdir");
    check_ret("chdir ..", chdir(".."), 0);
    if (dfd >= 0) {
        check_ret("fchdir(dfd)", fchdir(dfd), 0);
    }
    check_ret("chdir .. second", chdir(".."), 0);
    if (dfd >= 0) {
        check_ret("close dfd", close(dfd), 0);
    }
    check_ret("rmdir tst_dir", rmdir("tst_dir"), 0);
    printf("CASE_CLEANUP END\n");

    printf("SUMMARY total=%d failed=%d skipped=%d passed=%d\n",
           total_checks, failed_checks, skipped_checks,
           total_checks - failed_checks - skipped_checks);
    printf("REQ_ACCESS %s\n", req_access_seen ? "COVERED" : "MISSING");
    printf("REQ_CREATE %s\n", req_create_seen ? "COVERED" : "MISSING");
    printf("REQ_DELETE_RENAME %s\n", req_delete_or_rename_seen ? "COVERED" : "MISSING");
    printf("REQ_LISTDIR %s\n", req_listdir_seen ? "COVERED" : "MISSING");

    return failed_checks ? 1 : 0;
}
