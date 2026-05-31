#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

int main(void) {
    uid_t ruid = getuid();
    uid_t euid = geteuid();
    printf("Старт: Real UID = %d, Effective UID = %d\\n", ruid, euid);
    return 0;
}
