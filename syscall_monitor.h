#ifndef __SYSCALL_MONITOR_H__
#define __SYSCALL_MONITOR_H__

#define PATH_SIZE 256
#define XNAME_SIZE 128
#define XVALUE_SIZE 128
#define SMACK_LABEL_SIZE 256

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct syscall_event {
    __u64 ts;

    __s64 ret;
    __u32 syscall_nr;
    char comm[TASK_COMM_LEN];
    __u32 pid;
    __u32 tgid;
    __u32 euid;
    __u32 egid;

    /* Copy of userspace registers. */
    unsigned long args[6];
    char smack_subj[SMACK_LABEL_SIZE];
    char smack_obj[SMACK_LABEL_SIZE];
    char smack_exec[SMACK_LABEL_SIZE];
    char smack_mmap[SMACK_LABEL_SIZE];
    __u32 smack_flags;

    union {
        struct {
            char pathname[PATH_SIZE];
            int flags;
            __u32 mode;
            __u32 uid;
            __u32 gid;
            unsigned ino;
            unsigned perms;
        } open;
        struct {
            int dfd;
            char pathname[PATH_SIZE];
            int flags;
            __u32 mode;
            __u32 uid;
            __u32 gid;
            unsigned ino;
            unsigned perms;
        } openat;
        struct {
            char pathname[PATH_SIZE];
            __u32 mode;
            __u32 uid;
            __u32 gid;
            unsigned ino;
            unsigned perms;
        } creat;
        struct {
            char pathname[PATH_SIZE];
            __u32 mode;
            __u32 uid;
            __u32 gid;
            unsigned ino;
            unsigned perms;
        } mkdir;
        struct {
            int dfd;
            char pathname[PATH_SIZE];
            __u32 mode;
            __u32 uid;
            __u32 gid;
            unsigned ino;
            unsigned perms;
        } mkdirat;
        struct {
            char dir[PATH_SIZE];
        } chdir;
        struct {
            int fd;
        } fchdir;
        struct {
            char pathname[PATH_SIZE];
            __u32 mode;
            __u32 perms;
        } chmod;
        struct {
            int fd;
            __u32 mode;
            __u32 perms;
        } fchmod;
        struct {
            char pathname[PATH_SIZE];
            __u32 owner;
            __u32 group;
            __u32 perms;
        } chown;
        struct {
            int fd;
            __u32 owner;
            __u32 group;
            __u32 perms;
        } fchown;
        struct {
            unsigned int fd;
        } close;
        struct {
            int mask;
        } umask;
        struct {
            char pathname[PATH_SIZE];
        } unlink;
        struct {
            char pathname[PATH_SIZE];
        } rmdir;
        struct {
            unsigned int fd;
            //struct linux_dirent __user *dirent;
            //unsigned int count;
        } getdents;
        struct {
            unsigned int fd;
            //struct linux_dirent64 __user *dirent;
            //unsigned int count;
        } getdents64;
        struct {
            char pathname[PATH_SIZE];
            int mode;
        } access;
        struct {
            int dfd;
            char pathname[PATH_SIZE];
            int mode;
            int flags;
        } faccessat;
        struct {
            int dfd;
            char pathname[PATH_SIZE];
            int mode;
            int flags;
        } faccessat2;
        struct {
            char oldname[PATH_SIZE];
            char newname[PATH_SIZE];
        } link;
        struct {
            int olddfd;
            char oldname[PATH_SIZE];
            int newdfd;
            char newname[PATH_SIZE];
            int flags;
        } linkat;
        struct {
            char oldname[PATH_SIZE];
            char newname[PATH_SIZE];
        } symlink;
        struct {
            int dfd;
            char pathname[PATH_SIZE];
            int flags;
        } unlinkat;
        struct {
            char oldname[PATH_SIZE];
            char newname[PATH_SIZE];
        } rename;
        struct {
            int olddfd;
            char oldname[PATH_SIZE];
            int newdfd;
            char newname[PATH_SIZE];
        } renameat;
        struct {
            int olddfd;
            char oldname[PATH_SIZE];
            int newdfd;
            char newname[PATH_SIZE];
            int flags;
        } renameat2;
        struct getxattr {
            char pathname[PATH_SIZE];
            char name[XNAME_SIZE];
            union {
                __u8 value[XVALUE_SIZE];
                void *addr;
            };
            __u64 size;
        } getxattr;
        struct setxattr {
            char pathname[PATH_SIZE];
            char name[XNAME_SIZE];
            __u8 value[XVALUE_SIZE];
            __u64 size;
            int flags;
        } setxattr;
        struct {
            char pathname[PATH_SIZE];
            //char __user *__user *argv;
            //char __user *__user *envp;
            int umask;
        } execve;
        struct {
            int error_code;
        } exit_group;
        struct {
            int error_code;
        } exit;
    };
} __attribute__((packed));

struct monitor_config {
    __u32 enabled;
    __u32 filter_tst;
    __u64 smack_blob_sizes_addr;
};

#endif
