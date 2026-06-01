/*
 * test_setuid.c — тест для syscall'ов setuid/setgid/setreuid/setregid/
 *                 setresuid/setresgid.
 *
 * Должен запускаться через монитор от root, чтобы привилегированные
 * операции (setuid(0), setresuid(X,Y,Z)) реально проходили.
 *
 * Компиляция:
 *   gcc -g -O0 test_setuid.c -o tst_setuid
 *
 * Запуск через монитор (от root):
 *   sudo ./monitor run ./tst_setuid
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>

static void print_ids(const char *label) {
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    getresuid(&ruid, &euid, &suid);
    getresgid(&rgid, &egid, &sgid);
    printf("[%s] ruid=%d euid=%d suid=%d | rgid=%d egid=%d sgid=%d\n",
           label, ruid, euid, suid, rgid, egid, sgid);
}

static void try(const char *name, int ret) {
    if (ret == 0)
        printf("  %s -> ok\n", name);
    else
        printf("  %s -> err %d (%s)\n", name, errno, strerror(errno));
}

int main(void) {
    print_ids("START");

    /* --- setuid --- */
    printf("\n-- setuid --\n");
    /* Сохраняем root-euid на случай если позже захотим вернуться */
    try("setuid(0)",    syscall(SYS_setuid,    0));
    print_ids("after setuid(0)");

    /* --- setgid --- */
    printf("\n-- setgid --\n");
    try("setgid(0)",    syscall(SYS_setgid,    0));
    print_ids("after setgid(0)");

    /* --- setreuid: меняем только euid (ruid=-1 = не трогать) --- */
    printf("\n-- setreuid --\n");
    /* seteuid(1001) реализуется как setreuid(-1, 1001) */
    try("setreuid(-1, 1001)", syscall(SYS_setreuid, (uid_t)-1, 1001));
    print_ids("after setreuid(-1,1001)");
    /* восстанавливаем */
    try("setreuid(-1, 0)",    syscall(SYS_setreuid, (uid_t)-1, 0));
    print_ids("after setreuid(-1,0)");

    /* --- setregid: меняем только egid --- */
    printf("\n-- setregid --\n");
    try("setregid(-1, 1001)", syscall(SYS_setregid, (gid_t)-1, 1001));
    print_ids("after setregid(-1,1001)");
    try("setregid(-1, 0)",    syscall(SYS_setregid, (gid_t)-1, 0));
    print_ids("after setregid(-1,0)");

    /* --- setresuid: задаём ruid, euid, suid явно --- */
    printf("\n-- setresuid --\n");
    /* ruid=0, euid=1001, suid=0 */
    try("setresuid(0,1001,0)",  syscall(SYS_setresuid, 0, 1001, 0));
    print_ids("after setresuid(0,1001,0)");
    /* восстанавливаем root euid */
    try("setresuid(0,0,0)",     syscall(SYS_setresuid, 0, 0, 0));
    print_ids("after setresuid(0,0,0)");

    /* --- setresgid --- */
    printf("\n-- setresgid --\n");
    try("setresgid(0,1001,0)",  syscall(SYS_setresgid, 0, 1001, 0));
    print_ids("after setresgid(0,1001,0)");
    try("setresgid(0,0,0)",     syscall(SYS_setresgid, 0, 0, 0));
    print_ids("after setresgid(0,0,0)");

    print_ids("END");
    return 0;
}
