#include <linux/types.h>
#include "syscall_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "syscall_monitor.skel.h"
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <string.h>

#define PIN_PATH "/sys/fs/bpf/anis"
#define MAPS_PATH PIN_PATH "/maps"
#define PROGS_PATH PIN_PATH "/progs"
#define LINKS_PATH PIN_PATH "/links"

const char *BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		     "abcdefghijklmnopqrstuvwxyz"
		     "0123456789+/";

#if 0
static size_t base64_encode(const uint8_t *src, size_t len, char *dst)
{
    char *e = dst;
    size_t n;

    *e++ = '0';
    *e++ = 's';
    for (n = 0; n + 2 < len; n += 3) {
        *e++ = BASE64[src[0] >> 2];
        *e++ = BASE64[((src[0] & 0x03) << 4) | ((src[1] & 0xF0) >> 4)];
        *e++ = BASE64[((src[1] & 0x0F) << 2) | (src[2] >> 6)];
        *e++ = BASE64[src[2] & 0x3F];
        src += 3;
    }
    if (len - n == 2) {
        *e++ = BASE64[src[0] >> 2];
        *e++ = BASE64[((src[0] & 0x03) << 4) | ((src[1] & 0xF0) >> 4)];
        *e++ = BASE64[(src[1] & 0x0F) << 2];
        *e++ = '=';
    } else if (len - n == 1) {
        *e++ = BASE64[src[0] >> 2];
        *e++ = BASE64[(src[0] & 0x03) << 4];
        *e++ = '=';
        *e++ = '=';
    }
    *e = '\0';

    return e - dst;
}
#endif

int findIndex(const char val)
{
    if ('A' <= val && val <= 'Z')
            return val - 'A';
    if ('a' <= val && val <= 'z')
            return val - 'a' + 26;
    if ('0' <= val && val <= '9')
            return val - '0' + 52;
    if (val == '+')
            return 62;
    if (val == '/')
            return 63;
    return -1;
}

int base64_decode(const __u8 *str, char *out)
{
    const size_t length = strlen((const char *)str);
    const __u8 *it = str;
    const __u8 *end = str + length;
    int acc;

    if ((length - 2) % 4 != 0)
            return 1;

    it += 2; // skip 0s

    while (it != end) {
        const __u8 b1 = *it++;
        const __u8 b2 = *it++;
        const __u8 b3 = *it++; // might be the first padding byte
        const __u8 b4 =
                *it++; // might be the first or second padding byte

        const int i1 = findIndex(b1);
        const int i2 = findIndex(b2);

        acc = i1 << 2; // six bits came from the first byte
        acc |= i2 >> 4; // two bits came from the first byte
        *out++ = acc; // output the first byte

        if (b3 != '=') {
            const int i3 = findIndex(b3);

            acc = (i2 & 0xF)
                  << 4; // four bits came from the second byte
            acc += i3 >> 2; // four bits came from the second byte
            *out++ = acc; // output the second byte

            if (b4 != '=') {
                const int i4 = findIndex(b4);

                acc = (i3 & 0x3)
                      << 6; // two bits came from the third byte
                acc |= i4; // six bits came from the third byte
                *out++ = acc; // output the third byte
            }
        }
    }

    *out = '\0'; // add the sigil for end of string
    return 0;
}

static inline bool is_string(const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len && buf[i] != '\0'; ++i) {
        if (!isprint(buf[i])) {
            return false;
        }
    }
    return i != len;
}

#define field_size(type, member) sizeof(((type *)0)->member)

char base64_xattr[(field_size(struct getxattr, value) + 2) / 3 * 4 + 1];
char smack_flags_names[256];

static void append_flag_name(char *buf, size_t sz, size_t *used,
                             const char *name)
{
    int n;

    if (*used >= sz) {
        return;
    }
    n = snprintf(buf + *used, sz - *used, "%s%s", *used ? "|" : "", name);
    if (n < 0 || (size_t)n >= (sz - *used)) {
        *used = sz;
        return;
    }
    *used += (size_t)n;
}

static void format_smack_flags_names(__u32 flags, char *buf, size_t sz)
{
    size_t used = 0;
    int bit;

    if (sz == 0) {
        return;
    }
    if (flags == 0) {
        snprintf(buf, sz, "none");
        return;
    }

    buf[0] = '\0';
    if (flags & 0x01) {
        append_flag_name(buf, sz, &used, "SMK_INODE_INSTANT");
    }
    if (flags & 0x02) {
        append_flag_name(buf, sz, &used, "SMK_INODE_TRANSMUTE");
    }
    if (flags & 0x04) {
        append_flag_name(buf, sz, &used, "SMK_INODE_CHANGED");
    }
    if (flags & 0x08) {
        append_flag_name(buf, sz, &used, "SMK_INODE_IMPURE");
    }
    for (bit = 4; bit < 32; bit++) {
        if (flags & (1U << bit)) {
            char unknown[32];
            snprintf(unknown, sizeof(unknown), "UNKNOWN_BIT_%d", bit);
            append_flag_name(buf, sz, &used, unknown);
        }
    }
}

#define sys_entry(e) [SYS_##e] = #e
static const char *syscall_names[500] = {
    sys_entry(open),     sys_entry(openat),     sys_entry(creat),
    sys_entry(mkdir),    sys_entry(mkdirat),    sys_entry(chdir),
    sys_entry(fchdir),   sys_entry(chmod),      sys_entry(fchmod),
    sys_entry(chown),    sys_entry(fchown),     sys_entry(close),
    sys_entry(exit),     sys_entry(exit_group), sys_entry(umask),
    sys_entry(unlink),   sys_entry(rmdir),      sys_entry(getdents),
#ifdef SYS_getdents64
    sys_entry(getdents64),
#endif
    sys_entry(access),   sys_entry(faccessat),
#ifdef SYS_faccessat2
    sys_entry(faccessat2),
#endif
    sys_entry(link),
#ifdef SYS_linkat
    sys_entry(linkat),
#endif
    sys_entry(symlink),
#ifdef SYS_unlinkat
    sys_entry(unlinkat),
#endif
    sys_entry(rename),   sys_entry(renameat),
#ifdef SYS_renameat2
    sys_entry(renameat2),
#endif
    sys_entry(getxattr),
    sys_entry(setxattr), sys_entry(execve),     sys_entry(execveat),
};
#undef sys_entry

static int handle_event(void *ctx, void *data, size_t len)
{
    struct syscall_event *e = data;
    format_smack_flags_names(e->smack_flags, smack_flags_names, sizeof(smack_flags_names));

    printf("{ \"syscall\": \"%s\", \"proc\": \"%s\", \"pid\": %d, \"euid\": %d, \"egid\": %d, "
           "\"smack_subj\": \"%s\", \"smack_obj\": \"%s\", "
           "\"smack_exec\": \"%s\", \"smack_mmap\": \"%s\", "
           "\"smack_flags\": %u, \"smack_flags_hex\": \"0x%x\", "
           "\"smack_flags_names\": \"%s\", ",
        syscall_names[e->syscall_nr], e->comm,
        e->pid, e->euid, e->egid,
        e->smack_subj, e->smack_obj,
        e->smack_exec, e->smack_mmap,
        e->smack_flags, e->smack_flags, smack_flags_names);

    switch (e->syscall_nr) {
    case SYS_open: printf(
            "\"pathname\": \"%s\", \"flags\": %d, \"mode\": %d, "
            "\"uid\": %u, \"gid\": %u, "
            "\"ino\": %u, \"perms\": %u, ",
            e->open.pathname, e->open.flags,
            e->open.mode, e->open.uid,
            e->open.gid, e->open.ino,
            e->open.perms);
        break;
    case SYS_openat: printf(
            "\"dfd\": %d, \"pathname\": \"%s\", \"flags\": %d, "
            "\"mode\": %d, \"uid\": %u, \"gid\": %u, "
            "\"ino\": %u, \"perms\": %u, ",
            e->openat.dfd, e->openat.pathname,
            e->openat.flags, e->openat.mode,
            e->openat.uid, e->openat.gid,
            e->openat.ino, e->openat.perms);
        break;
    case SYS_creat: printf(
            "\"pathname\": \"%s\", \"mode\": %d, "
            "\"uid\": %u, \"gid\": %u, "
            "\"ino\": %u, \"perms\": %u, ",
            e->creat.pathname, e->creat.mode,
            e->creat.uid, e->creat.gid,
            e->creat.ino, e->creat.perms);
        break;
    case SYS_mkdir: printf("\"pathname\": \"%s\", \"mode\": %d, "
            "\"uid\": %u, \"gid\": %u, "
            "\"ino\": %u, \"perms\": %u, ",
            e->mkdir.pathname, e->mkdir.mode,
            e->mkdir.uid, e->mkdir.gid,
            e->mkdir.ino, e->mkdir.perms);
        break;
    case SYS_mkdirat: printf(
            "\"dfd\": %d, \"pathname\": \"%s\", \"mode\": %d, "
            "\"uid\": %u, \"gid\": %u, "
            "\"ino\": %u, \"perms\": %u, ",
            e->mkdirat.dfd, e->mkdirat.pathname,
            e->mkdirat.mode, e->mkdirat.uid,
            e->mkdirat.gid, e->mkdirat.ino,
            e->mkdirat.perms);
        break;
    case SYS_chdir: printf(
            "\"dir\": \"%s\", ",
            e->chdir.dir);
        break;
    case SYS_fchdir: printf(
            "\"fd\": %d, ",
            e->fchdir.fd);
        break;
    case SYS_chmod: printf(
            "\"pathname\": \"%s\", \"mode\": %d, \"perms\": %u,",
            e->chmod.pathname, e->chmod.mode,
            e->chmod.perms);
        break;
    case SYS_fchmod: printf(
            "\"fd\": %d, \"mode\": %d, \"perms\": %u, ",
            e->fchmod.fd, e->fchmod.mode,
            e->fchmod.perms);
        break;
    case SYS_chown: printf(
            "\"pathname\": \"%s\", \"owner\": %d, \"group\": %d, "
            "\"perms\": %u,",
            e->chown.pathname, e->chown.owner,
            e->chown.group, e->chown.perms);
        break;
    case SYS_fchown: printf(
            "\"fd\": \"%d\", \"owner\": %d, \"group\": %d, "
            "\"perms\": %u, ",
            e->fchown.fd, e->fchown.owner,
            e->fchown.group, e->fchown.perms);
        break;
    case SYS_close: printf(
            "\"fd\": %u,",
            e->close.fd);
        break;
    case SYS_umask: printf(
            "\"mask\": %d,",
            e->umask.mask);
        break;
    case SYS_unlink: printf(
            "\"pathname\": \"%s\",",
            e->unlink.pathname);
        break;
    case SYS_rmdir: printf(
            "\"pathname\": \"%s\",",
            e->rmdir.pathname);
        break;
    case SYS_getdents: printf(
            "\"fd\": %u,",
            e->getdents.fd);
        break;
#ifdef SYS_getdents64
    case SYS_getdents64: printf(
            "\"fd\": %u,",
            e->getdents64.fd);
        break;
#endif
    case SYS_access: printf(
            "\"pathname\": \"%s\", \"mode\": %d,",
            e->access.pathname, e->access.mode);
        break;
    case SYS_faccessat: printf(
            "\"dfd\": %d, \"pathname\": \"%s\", \"mode\": %d, \"flags\": %d,",
            e->faccessat.dfd, e->faccessat.pathname,
            e->faccessat.mode, e->faccessat.flags);
        break;
#ifdef SYS_faccessat2
    case SYS_faccessat2: printf(
            "\"dfd\": %d, \"pathname\": \"%s\", \"mode\": %d, \"flags\": %d,",
            e->faccessat2.dfd, e->faccessat2.pathname,
            e->faccessat2.mode, e->faccessat2.flags);
        break;
#endif
    case SYS_link: printf(
            "\"oldname\": \"%s\", \"newname\": \"%s\",",
            e->link.oldname, e->link.newname);
        break;
#ifdef SYS_linkat
    case SYS_linkat: printf(
            "\"olddfd\": %d, \"oldname\": \"%s\", "
            "\"newdfd\": %d, \"newname\": \"%s\", \"flags\": %d,",
            e->linkat.olddfd, e->linkat.oldname,
            e->linkat.newdfd, e->linkat.newname, e->linkat.flags);
        break;
#endif
    case SYS_symlink: printf(
            "\"oldname\": \"%s\", \"newname\": \"%s\",",
            e->symlink.oldname, e->symlink.newname);
        break;
#ifdef SYS_unlinkat
    case SYS_unlinkat: printf(
            "\"dfd\": %d, \"pathname\": \"%s\", \"flags\": %d,",
            e->unlinkat.dfd, e->unlinkat.pathname, e->unlinkat.flags);
        break;
#endif
    case SYS_rename: printf(
            "\"oldname\": \"%s\", \"newname\": \"%s\",",
            e->rename.oldname, e->rename.newname);
        break;
    case SYS_renameat: printf(
            "\"olddfd\": %d, \"oldname\": \"%s\", "
            "\"newdfd\": %d, \"newname\": \"%s\",",
            e->renameat.olddfd, e->renameat.oldname,
            e->renameat.newdfd, e->renameat.newname);
        break;
#ifdef SYS_renameat2
    case SYS_renameat2: printf(
            "\"olddfd\": %d, \"oldname\": \"%s\", "
            "\"newdfd\": %d, \"newname\": \"%s\", \"flags\": %d,",
            e->renameat2.olddfd, e->renameat2.oldname,
            e->renameat2.newdfd, e->renameat2.newname, e->renameat2.flags);
        break;
#endif
    case SYS_getxattr: {
        char *decoded_value;
        __u8 *raw_value = e->getxattr.value;
        __u64 raw_size = e->getxattr.size;
        ssize_t size = e->ret;        
        if (raw_size <= 0 || size <= 0) {
            decoded_value = ""; // getxattr fails
        } else if (is_string(raw_value, size + 1)) {
            if (size > 2 &&
                raw_value[0] == 'O' &&
                raw_value[1] == 's') {
                base64_decode(raw_value, base64_xattr);
                decoded_value = base64_xattr;
            } else {
                static char raw[sizeof e->getxattr.value];
                strncpy(raw, (char *)raw_value, size);
                raw[size] = '\0';
                decoded_value = raw;
            }
        } else {
            fprintf(stderr, "Unknown value format in getxattr\n");
            abort();
        }

        printf(
            "\"pathname\": \"%s\", \"name\": \"%s\", "
            "\"value\": \"%s\", \"size\": %llu,",
            e->getxattr.pathname, e->getxattr.name, decoded_value,
            raw_size);
        break;
    }
    case SYS_setxattr: {
        //char *value;
        //struct setxattr *sxattr = &e->setxattr;
        //if (is_string(sxattr->value, sxattr->size)) {
        //    value = sxattr->value;
        //    value[sxattr->size] = '\0';
        //} else {
        //    base64_encode(sxattr->value, sxattr->size, base64_xattr);
        //    value = base64_xattr;
        //}

        printf(
            "\"pathname\": \"%s\", \"name\": \"%s\", "
            "\"value\": \"%s\", \"size\": %llu, \"flags\": %d,",
            e->setxattr.pathname, e->setxattr.name, e->setxattr.value,
            e->setxattr.size, e->setxattr.flags);
        break;
    }
    case SYS_execve: printf(
              "\"pathname\": \"%s\", "
              "\"umask\": %d, ",
              e->execve.pathname,
              e->execve.umask);
        break;
    case SYS_exit: printf(
              "\"error_code\": %d,",
              e->exit.error_code);
        break;
    case SYS_exit_group: printf(
              "\"error_code\": %d,",
              e->exit_group.error_code);
        break;
    default:
        fprintf(stderr, "Unknown syscall %d\n", e->syscall_nr);
        abort();
    }
    printf(" \"ret\": %lld }\n", e->ret);

    return 0;
}

static volatile int exited = 0;

void set_exited(int sig)
{
    exited = 1;
}

static bool lsm_has_smack(void)
{
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) {
        return false;
    }

    char buf[1024];
    bool has = false;
    if (fgets(buf, sizeof(buf), f) != NULL) {
        has = strstr(buf, "smack") != NULL;
    }
    fclose(f);
    return has;
}

static __u64 find_kallsyms_symbol_addr(const char *symbol, bool *found)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        return 0;
    }

    char line[512];
    __u64 addr = 0;
    bool hit = false;

    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned long long cur_addr = 0;
        char type = 0;
        char name[256] = {};

        if (sscanf(line, "%llx %c %255s", &cur_addr, &type, name) != 3) {
            continue;
        }
        if (strcmp(name, symbol) != 0) {
            continue;
        }
        addr = (__u64)cur_addr;
        hit = true;
        break;
    }
    fclose(f);

    if (found) {
        *found = hit;
    }
    return addr;
}

static void warn_if_smack_unavailable(void)
{
    static bool warned = false;
    if (warned) {
        return;
    }
    warned = true;

    if (!lsm_has_smack()) {
        fprintf(stderr,
                "Warning: Smack is not active in /sys/kernel/security/lsm; "
                "smack_* fields will be empty.\n");
    }
}


int
load(void)
{
    struct syscall_monitor_bpf *skel;
    int err;

    warn_if_smack_unavailable();

    if (!(skel = syscall_monitor_bpf__open_and_load())) {
        fprintf(stderr, "Failed to create skeleton\n");
        return 1;
    }

    if ((err = mkdir(PIN_PATH, 0700)) != 0) {
        fprintf(stderr, "Failed to mkdir " PIN_PATH "; error %d\n", err);
        goto END;
    }

    if ((err = mkdir(MAPS_PATH, 0700)) != 0) {
        fprintf(stderr, "Failed to mkdir " MAPS_PATH "; error %d\n", err);
        goto END;
    }
    if ((err = bpf_map__pin(skel->maps.events, MAPS_PATH "/events")) != 0) {
        fprintf(stderr, "Failed to pin map 'events'; error %d\n", err);
        goto END;
    }

    if ((err = bpf_map__pin(skel->maps.config_map, MAPS_PATH "/config_map")) != 0) {
        fprintf(stderr, "Failed to pin map 'config_map'; error %d\n", err);
        goto END;
    }

    int cfg_fd;
    if ((cfg_fd = bpf_obj_get(MAPS_PATH "/config_map")) < 0) {
        err = cfg_fd;
        fprintf(stderr, "Failed to open the pinned map 'config_map'; error %d\n", err);
        goto END;
    }
    struct monitor_config cfg = {0};
    bool sym_found = false;
    __u32 key = 0;

    cfg.smack_blob_sizes_addr = find_kallsyms_symbol_addr("smack_blob_sizes", &sym_found);
    if (!cfg.smack_blob_sizes_addr) {
        if (sym_found) {
            fprintf(stderr, "Warning: symbol 'smack_blob_sizes' found but address is hidden; "
                    "smack_* fields may stay empty.\n");
        } else {
            fprintf(stderr, "Warning: symbol 'smack_blob_sizes' not found in /proc/kallsyms; "
                    "smack_* fields may stay empty.\n");
        }
    }

    cfg.enabled = 0;
    cfg.filter_tst = 1;
    bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY);


    if ((err = mkdir(PROGS_PATH, 0700)) != 0) {
        fprintf(stderr, "Failed to mkdir " PROGS_PATH "; error %d\n", err);
        goto END;
    }
    if ((err = bpf_object__pin_programs(skel->obj, PROGS_PATH)) != 0) {
        fprintf(stderr, "Failed to pin programs; error %d\n", err);
        goto END;
    }
    if ((err = syscall_monitor_bpf__attach(skel)) != 0) { // attach all links
        fprintf(stderr, "Failed to attach links; error %d\n", err);
        goto END;
    }

    if ((err = mkdir(LINKS_PATH, 0700)) != 0) {
        fprintf(stderr, "Failed to mkdir " LINKS_PATH "; error %d\n", err);
        goto END;
    }
    struct bpf_link **links = (struct bpf_link **)&skel->links;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, skel->obj) {
        struct bpf_link *link = *links++;
        const char *name = bpf_program__name(prog);

        char path[sizeof LINKS_PATH + 256];
        snprintf(path, sizeof(path), LINKS_PATH "/%s", name);

        if ((err = bpf_link__pin(link, path)) != 0) {
            fprintf(stderr, "Failed to pin link '%s'; error %d\n", name, err);
            goto END;
        }
    }
END:
    syscall_monitor_bpf__destroy(skel);
    if (err != 0) {
        system("rm -rf " PIN_PATH);
    }
    return (err == 0 ? 0 : 1);
}

int
unload(void)
{
    int err = system("rm -rf " PIN_PATH);
    return (err == 0 ? 0 : 1);
}

int
run(int argc, char *argv[])
{
    struct ring_buffer *rb = 0;
    int err = 0;

    warn_if_smack_unavailable();

    int cfg_fd;
    if ((cfg_fd = bpf_obj_get(MAPS_PATH "/config_map")) < 0) {
        fprintf(stderr, "Failed to open the pinned map 'config_map'; error %d\n", cfg_fd);
        return 1;
    }
    struct monitor_config cfg = {0};
    __u32 key = 0;

    if (bpf_map_lookup_elem(cfg_fd, &key, &cfg) != 0) {
        cfg.filter_tst = 1;
        cfg.smack_blob_sizes_addr = 0;
    }
    cfg.enabled = 1;
    bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY);

    int events_fd;
    if ((events_fd = bpf_obj_get(MAPS_PATH "/events")) < 0) {
        fprintf(stderr, "Failed to open the pinned map 'events'; error %d\n", events_fd);
        err = events_fd;
        goto END;
    }

    if (!(rb = ring_buffer__new(events_fd, handle_event, 0, 0))) {
        fprintf(stderr, "Failed to allocate the new ring buffer\n");
        err = 1;
        goto END;
    }

    signal(SIGINT, set_exited);

    pid_t child = 0;
    if ((err = child = fork()) < 0) {
        fprintf(stderr, "%s\n", strerror(errno));
        exited = 1;
    } else if (child == 0) {
        ring_buffer__free(rb);
        execvp(argv[2], &argv[2]);
        fprintf(stderr, "%s: %s\n", argv[2], strerror(errno));
        return 127;
    }

    int status;
    while (!exited) {
        if ((err = ring_buffer__poll(rb, 100)) < 0) {
            if (err != -EINTR) {
                 fprintf(stderr, "Failed to poll the ring buffer; error %d\n", err);
            }
            kill(child, SIGKILL);
            exited = 1;
        } else if (err == 0 && waitpid(child, &status, WNOHANG) > 0) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
                err = 1; // execvp failed
            }
            exited = 1;
        }
    }

END:
    if (rb) ring_buffer__free(rb);

    cfg.enabled = 0;
    bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY);

    return err == 0 ? 0 : 1;
}

int
main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s cmd args...\n", argv[0]);
        return 1;
    } else if (strcmp(argv[1], "load") == 0) {
        return load();
    } else if (strcmp(argv[1], "unload") == 0) {
        return unload();
    } else if (strcmp(argv[1], "run") == 0) {
        return run(argc, argv);
    } else {
        fprintf(stderr, "Usage: %s cmd args...\n", argv[0]);
        return 1;
    }
}
