#define _GNU_SOURCE
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>

int main(void) {
    int fd;
    fd = syscall(SYS_creat, "/tmp/tst_creat0",  0644); if (fd >= 0) close(fd);
    fd = syscall(SYS_creat, "/tmp/tst_creat1",  0644); if (fd >= 0) close(fd);
    fd = syscall(SYS_creat, "/tmp/tst_creat2",  0644); if (fd >= 0) close(fd);
    fd = syscall(SYS_creat, "/tmp/tst_creat3",  0644); if (fd >= 0) close(fd);
    fd = syscall(SYS_creat, "/tmp/tst_creat4",  0644); if (fd >= 0) close(fd);
    fd = syscall(SYS_creat, "/tmp/tst_creat5",  0644); if (fd >= 0) close(fd);
    fd = syscall(SYS_creat, "/tmp/tst_creat6",  0644); if (fd >= 0) close(fd);
    fd = syscall(SYS_creat, "/tmp/tst_creat7",  0644); if (fd >= 0) close(fd);
    fd = syscall(SYS_creat, "/tmp/tst_creat8",  0644); if (fd >= 0) close(fd);
    fd = syscall(SYS_creat, "/tmp/tst_creat9",  0644); if (fd >= 0) close(fd);
    return 0;
}
