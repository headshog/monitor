// TEST.c
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

static void must(int ok, const char *what) {
    if (!ok) {
        perror(what);
        exit(1);
    }
}

int main(void) {
    must(prctl(PR_SET_NAME, "tst_TEST", 0, 0, 0) == 0, "prctl(PR_SET_NAME)");

    umask(022);
    must(mkdir("tst_dir", 0755) == 0 || errno == EEXIST, "mkdir");

    int dfd = open("tst_dir", O_RDONLY | O_DIRECTORY);
    must(dfd >= 0, "open dir");

    must(chdir("tst_dir") == 0, "chdir");
    int fd = creat("a.txt", 0640);
    must(fd >= 0, "creat");
    must(write(fd, "hello\n", 6) == 6, "write");
    must(close(fd) == 0, "close");

    must(chmod("a.txt", 0600) == 0, "chmod");
    fd = open("a.txt", O_RDONLY);
    must(fd >= 0, "open");
    must(fchmod(fd, 0644) == 0, "fchmod");
    must(fchown(fd, getuid(), getgid()) == 0, "fchown");
    must(close(fd) == 0, "close2");
    must(chown("a.txt", getuid(), getgid()) == 0, "chown");

    must(symlink("a.txt", "a.link") == 0, "symlink");
    must(link("a.txt", "a.hard") == 0, "link");

    const char *val = "value";
    must(setxattr("a.txt", "user.demo", val, strlen(val), 0) == 0, "setxattr");
    char buf[64];
    must(getxattr("a.txt", "user.demo", buf, sizeof(buf)) >= 0, "getxattr");

    DIR *d = opendir(".");
    must(d != NULL, "opendir");
    while (readdir(d)) {}
    closedir(d);

    must(unlink("a.link") == 0, "unlink a.link");
    must(unlink("a.hard") == 0, "unlink a.hard");
    must(unlink("a.txt") == 0, "unlink a.txt");

    must(chdir("..") == 0, "chdir ..");
    must(fchdir(dfd) == 0, "fchdir");
    must(chdir("..") == 0, "chdir ..2");
    must(close(dfd) == 0, "close dfd");
    must(rmdir("tst_dir") == 0, "rmdir");

    return 0;
}
