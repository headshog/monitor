#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syscall_monitor.h"
#include "utils.h"


char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct monitor_config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct syscall_args);
} args_map SEC(".maps");

struct syscall_args {
    __u64 args[6];
};

struct newdir_data {
    umode_t        i_mode;
    kuid_t        i_uid;
    kgid_t        i_gid;
    unsigned long    i_ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct newdir_data);
} mkdir_map SEC(".maps");

struct mkdir_dentry_data {
    struct dentry *dentry;
    int depth;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct mkdir_dentry_data);
} mkdir_dentry SEC(".maps");

struct chmod_ctx {
    struct path *path;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct chmod_ctx);
} chmod_map SEC(".maps");

struct chmod_data {
    u32    i_mode;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct chmod_data);
} chmod_data_map SEC(".maps");

struct chown_ctx {
    struct path *path;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct chown_ctx);
} chown_map SEC(".maps");

struct chown_data {
    u32    i_mode;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct chown_data);
} chown_data_map SEC(".maps");

struct execve_data {
    char   pathname[PATH_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct execve_data);
} execve_map SEC(".maps");


static __always_inline int should_monitor(void)
{
    u32 key = 0;
    struct monitor_config *cfg = bpf_map_lookup_elem(&config_map, &key);

    if (!cfg || !cfg->enabled) {
        return 0;
    }
    if (!cfg->filter_tst) {
        return 1;
    }

    u32 comm[4] = {0};
    bpf_get_current_comm(&comm, sizeof comm);
    char prefix[4] = "tst_";
    return *(u32 *)prefix == comm[0]; // comm starts with "tst_"
}

SEC("kprobe/chmod_common")
int BPF_KPROBE(handle_chmod_common)
{
    if (!should_monitor()) {
        return 0;
    }    

    u64 id = bpf_get_current_pid_tgid();

    struct chmod_ctx data = {};
    data.path = (struct path *)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&chmod_map, &id, &data, BPF_ANY);
    bpf_printk("kprobe/chmod_common: %llu", id);

    return 0;
}

SEC("kretprobe/chmod_common")
int BPF_KRETPROBE(handle_chmod_common_ret)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();

    struct chmod_ctx *cctx;
    if (!(cctx = bpf_map_lookup_elem(&chmod_map, &id))) {
        bpf_printk("chmod_common: no chmod_ctx found");
        return 0;
    }

    long ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        goto CLEANUP;
    }

    struct path *path = cctx->path;
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);

    if (!inode) {
        bpf_printk("chmod_common: dentry without d_inode");
        goto CLEANUP;
    }

    struct chmod_data data = {};
    data.i_mode = BPF_CORE_READ(inode, i_mode);
    bpf_map_update_elem(&chmod_data_map, &id, &data, BPF_ANY);

CLEANUP:
    bpf_map_delete_elem(&chmod_map, &id);
    return 0;
}

SEC("kprobe/chown_common")
int BPF_KPROBE(handle_chown_common)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();

    struct chown_ctx data = {};
    data.path = (struct path *)PT_REGS_PARM1(ctx);

    bpf_map_update_elem(&chown_map, &id, &data, BPF_ANY);

    return 0;
}

SEC("kretprobe/chown_common")
int BPF_KRETPROBE(handle_chown_common_ret)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();

    struct chmod_ctx *cctx;
    if (!(cctx = bpf_map_lookup_elem(&chown_map, &id))) {
        bpf_printk("chown_common: no chown_ctx found");
        return 0;
    }

    long ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        goto CLEANUP;
    }

    struct path *path = cctx->path;
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);

    if (!inode) {
        bpf_printk("chown_common: dentry without d_inode");
        goto CLEANUP;
    }

    struct chown_data data = {};
    data.i_mode = BPF_CORE_READ(inode, i_mode);
    bpf_map_update_elem(&chown_data_map, &id, &data, BPF_ANY);

CLEANUP:
    bpf_map_delete_elem(&chown_map, &id);
    return 0;
}

static __always_inline
int
save_syscall_args(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_monitor()) {
        return 0;
    }

    u32 key = 0;

    struct syscall_args args = {};
    BPF_CORE_READ_INTO(&args.args, ctx, args);

    long ret;
    if ((ret = bpf_map_update_elem(&args_map, &key, &args, BPF_ANY)) < 0) {
        bpf_printk("update elem returns %ld", ret);
    }

    return 1;
}

static __always_inline
struct syscall_event *
read_syscall_args(struct trace_event_raw_sys_exit *ctx)
{
    if (!should_monitor()) {
        return 0;
    }

    u32 key = 0;

    struct syscall_args *args;
    if (!(args = bpf_map_lookup_elem(&args_map, &key))) {
        bpf_printk("lookup failed");
        return 0;
    }
    bpf_map_delete_elem(&args_map, &key);

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof *e, 0);
    if (!e) {
        bpf_printk("ringbuffer overflow");
        return 0;
    }

    e->ts = bpf_ktime_get_ns();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & ((1uLL << 32) - 1);
    e->tgid = pid_tgid >> 32;

    u64 uid_gid = bpf_get_current_uid_gid();
    e->euid = uid_gid & ((1uLL << 32) - 1);
    e->egid = uid_gid >> 32;

    bpf_get_current_comm(&e->comm, sizeof e->comm);
    
    e->syscall_nr = ctx->id;
    __builtin_memcpy(e->args, args->args, sizeof e->args);

    e->ret = ctx->ret;

    return e;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_enter_open(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_open")
int trace_exit_open(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->open.pathname, (const char *)e->args[0]);
    e->open.flags = e->args[1];
    e->open.mode = e->args[2];

    if (e->ret < 0) {
        goto END;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct file *file = bpf_get_task_file(task, e->ret);
    const struct inode *i = bpf_file_inode(file);

    e->open.uid = BPF_CORE_READ(i, i_uid).val;
    e->open.gid = BPF_CORE_READ(i, i_gid).val;
    e->open.ino = BPF_CORE_READ(i, i_ino);
    e->open.perms = BPF_CORE_READ(i, i_mode);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->openat.dfd = e->args[0];
    bpf_get_path(e->openat.pathname, (const char *)e->args[1]);
    e->openat.flags = e->args[2];
    e->openat.mode = e->args[3];

    if (e->ret < 0) {
        goto END;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct file *file = bpf_get_task_file(task, e->ret);
    const struct inode *i = bpf_file_inode(file);

    e->openat.uid = BPF_CORE_READ(i, i_uid).val;
    e->openat.gid = BPF_CORE_READ(i, i_gid).val;
    e->openat.ino = BPF_CORE_READ(i, i_ino);
    e->openat.perms = BPF_CORE_READ(i, i_mode);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_enter_creat(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_creat")
int trace_exit_creat(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->creat.pathname, (const char *)e->args[0]);
    e->creat.mode = e->args[1];

    if (e->ret < 0) {
        goto END;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct file *file = bpf_get_task_file(task, e->ret);
    const struct inode *i = bpf_file_inode(file);

    e->creat.uid = BPF_CORE_READ(i, i_uid).val;
    e->creat.gid = BPF_CORE_READ(i, i_gid).val;
    e->creat.ino = BPF_CORE_READ(i, i_ino);
    e->creat.perms = BPF_CORE_READ(i, i_mode);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdir")
int trace_enter_mkdir(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("kprobe/vfs_mkdir")
int BPF_KPROBE(handle_vfs_mkdir,
               struct user_namespace *mnt_userns,
               struct inode *dir,
               struct dentry *dentry,
               umode_t mode)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();

    struct mkdir_dentry_data *first_dentry;
    if (!(first_dentry = bpf_map_lookup_elem(&mkdir_dentry, &id))) {
        struct mkdir_dentry_data data = {};
        data.dentry = dentry;
        data.depth = 0;
        bpf_map_update_elem(&mkdir_dentry, &id, &data, BPF_ANY);
    } else {
        ++ first_dentry->depth;
        bpf_map_update_elem(&mkdir_dentry, &id, first_dentry, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/vfs_mkdir")
int BPF_KRETPROBE(handle_vfs_mkdir_ret)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    struct mkdir_dentry_data *dentryp = bpf_map_lookup_elem(&mkdir_dentry, &id);
    if (!dentryp) {
        bpf_printk("kretprobe/vfs_mkdir: no dentry for %lu", id);
        return 0;
    } else if (dentryp->depth > 0) {
        -- dentryp->depth;
        bpf_map_update_elem(&mkdir_dentry, &id, dentryp, BPF_ANY);
        return 0;
    }
    bpf_map_delete_elem(&mkdir_dentry, &id);

    struct dentry *dentry = dentryp->dentry;
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) {
        bpf_printk("kretprobe/vfs_mkdir: no inode");
        return 0;
    }

    struct newdir_data data = {};
    data.i_uid = BPF_CORE_READ(inode, i_uid);
    data.i_gid = BPF_CORE_READ(inode, i_gid);
    data.i_ino = BPF_CORE_READ(inode, i_ino);
    data.i_mode = BPF_CORE_READ(inode, i_mode);

    bpf_map_update_elem(&mkdir_map, &id, &data, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_mkdir")
int trace_exit_mkdir(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->mkdir.pathname, (char *)e->args[0]);
    e->mkdir.mode = e->args[1];

    if (e->ret != 0) {
        goto END;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct newdir_data *data;
    if (!(data = bpf_map_lookup_elem(&mkdir_map, &pid_tgid))) {
        bpf_printk("Mkdir without saved data");
        goto END;
    }

    e->mkdir.uid   = data->i_uid.val;
    e->mkdir.gid   = data->i_gid.val;
    e->mkdir.ino   = data->i_ino;
    e->mkdir.perms = data->i_mode;

    bpf_map_delete_elem(&mkdir_map, &pid_tgid);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int trace_enter_mkdirat(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_mkdirat")
int trace_exit_mkdirat(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->mkdirat.dfd = e->args[0];
    bpf_get_path(e->mkdirat.pathname, (char *)e->args[1]);
    e->mkdirat.mode = e->args[2];

    if (e->ret != 0) {
        goto END;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct newdir_data *data;
    if (!(data = bpf_map_lookup_elem(&mkdir_map, &pid_tgid))) {
        bpf_printk("Mkdirat without saved data");
        goto END;
    }

    e->mkdirat.uid   = data->i_uid.val;
    e->mkdirat.gid   = data->i_gid.val;
    e->mkdirat.ino   = data->i_ino;
    e->mkdirat.perms = data->i_mode;

    bpf_map_delete_elem(&mkdir_map, &pid_tgid);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chdir")
int trace_enter_chdir(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_chdir")
int trace_exit_chdir(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->chdir.dir, (const char *)e->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchdir")
int trace_enter_fchdir(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_fchdir")
int trace_exit_fchdir(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->fchdir.fd = e->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_enter_chmod(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_chmod")
int trace_exit_chmod(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->chmod.pathname, (char *)e->args[0]);
    e->chmod.mode = e->args[1];

    if (e->ret < 0) {
        goto END;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct chmod_data *data;
    if (!(data = bpf_map_lookup_elem(&chmod_data_map, &pid_tgid))) {
        bpf_printk("chmod without saved data");
        goto END;
    }

    e->chmod.perms = data->i_mode;

    bpf_map_delete_elem(&chmod_data_map, &pid_tgid);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int trace_enter_fchmod(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_fchmod")
int trace_exit_fchmod(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->fchmod.fd = e->args[0];
    e->fchmod.mode = e->args[1];

    if (e->ret < 0) {
        goto END;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct chmod_data *data;
    if (!(data = bpf_map_lookup_elem(&chmod_data_map, &pid_tgid))) {
        bpf_printk("chmod without saved data");
        goto END;
    }

    e->fchmod.perms = data->i_mode;
    bpf_map_delete_elem(&chmod_data_map, &pid_tgid);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chown")
int trace_enter_chown(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_chown")
int trace_exit_chown(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->chown.pathname, (char *)e->args[0]);
    e->chown.owner = e->args[1];
    e->chown.group = e->args[2];

    if (e->ret < 0) {
        goto END;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct chown_data *data;
    if (!(data = bpf_map_lookup_elem(&chown_data_map, &pid_tgid))) {
        bpf_printk("chown without saved data");
        goto END;
    }

    e->chown.perms = data->i_mode;

    bpf_map_delete_elem(&chown_data_map, &pid_tgid);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchown")
int trace_enter_fchown(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_fchown")
int trace_exit_fchown(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->fchown.fd = e->args[0];
    e->fchown.owner = e->args[1];
    e->fchown.group = e->args[2];

    if (e->ret < 0) {
        goto END;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct chown_data *data;
    if (!(data = bpf_map_lookup_elem(&chown_data_map, &pid_tgid))) {
        bpf_printk("chmod without saved data");
        goto END;
    }

    e->fchown.perms = data->i_mode;
    bpf_map_delete_elem(&chown_data_map, &pid_tgid);

END:
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_enter_close(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_close")
int trace_exit_close(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->close.fd = e->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_umask")
int trace_enter_umask(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_umask")
int trace_exit_umask(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->umask.mask = e->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_enter_unlink(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int trace_exit_unlink(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->unlink.pathname, (char *)e->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int trace_enter_rmdir(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_rmdir")
int trace_exit_rmdir(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->rmdir.pathname, (char *)e->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents")
int trace_enter_getdents(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_getdents")
int trace_exit_getdents(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->getdents.fd = e->args[0];
    // e->getdents.dirent = e->args[1];
    // e->getdents.count = e->args[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_link")
int trace_enter_link(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_link")
int trace_exit_link(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->link.oldname, (char *)e->args[0]);
    bpf_get_path(e->link.newname, (char *)e->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int trace_enter_symlink(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_symlink")
int trace_exit_symlink(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->symlink.oldname, (char *)e->args[0]);
    bpf_get_path(e->symlink.newname, (char *)e->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getxattr")
int trace_enter_getxattr(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_getxattr")
int trace_exit_getxattr(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->getxattr.pathname, (char *)e->args[0]);
    bpf_get_xattr_name(e->getxattr.name, (char *)e->args[1]);
    e->getxattr.addr = (void *)e->args[2];
    e->getxattr.size = e->args[3];
    bpf_get_xattr_value(e->getxattr.value, e->getxattr.size, e->getxattr.addr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setxattr")
int trace_enter_setxattr(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_setxattr")
int trace_exit_setxattr(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->setxattr.pathname, (char *)e->args[0]);
    bpf_get_xattr_name(e->setxattr.name, (char *)e->args[1]);
    e->setxattr.size = e->args[3];
    e->setxattr.flags = e->args[4];
    bpf_get_xattr_value(e->setxattr.value, e->setxattr.size, (uint8_t *)e->args[2]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    if (e->ret < 0) {
        bpf_get_path(e->execve.pathname, (char *)e->args[0]);
    } else {
        // get pathname from map
        u64 pid_tgid = bpf_get_current_pid_tgid();
        struct execve_data *data;
        if (!(data = bpf_map_lookup_elem(&execve_map, &pid_tgid))) {
            bpf_printk("execve without saved data");
        } else {
            __builtin_memcpy(e->execve.pathname, data->pathname, sizeof data->pathname);
            bpf_map_delete_elem(&execve_map, &pid_tgid);
        }
    }
    //e->execve.argv = e->args[1];
    //e->execve.envp = e->args[2];
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->execve.umask = BPF_CORE_READ(task, fs, umask);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    if (!should_monitor()) {
        return 0;
    }

    u32 loc = ctx->__data_loc_filename;

    u32 offset = loc & 0xffff;
    char *filename = (char *)ctx + offset;
    struct execve_data data = {};
    bpf_probe_read_kernel_str(data.pathname, sizeof data.pathname, filename);

    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&execve_map, &id, &data, BPF_ANY);

    return 0;
}
 
SEC("tracepoint/syscalls/sys_enter_exit")
int trace_enter_exit(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_monitor()) {
        return 0;
    }

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof *e, 0);
    if (!e) {
        bpf_printk("ringbuffer overflow");
        return 0;
    }

    e->ts = bpf_ktime_get_ns();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & ((1uLL << 32) - 1);
    e->tgid = pid_tgid >> 32;

    bpf_get_current_comm(&e->comm, sizeof e->comm);

    e->syscall_nr = ctx->id;
    struct syscall_args args = {};
    BPF_CORE_READ_INTO(&args.args, ctx, args);
     __builtin_memcpy(e->args, &args.args, sizeof e->args);

    e->ret = 0;
    e->exit.error_code = e->args[0];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int trace_enter_exit_group(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_monitor()) {
        return 0;
    }

    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof *e, 0);
    if (!e) {
        bpf_printk("ringbuffer overflow");
        return 0;
    }

    e->ts = bpf_ktime_get_ns();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & ((1uLL << 32) - 1);
    e->tgid = pid_tgid >> 32;

    bpf_get_current_comm(&e->comm, sizeof e->comm);

    e->syscall_nr = ctx->id;
    struct syscall_args args = {};
    BPF_CORE_READ_INTO(&args.args, ctx, args);
     __builtin_memcpy(e->args, &args.args, sizeof e->args);

    e->ret = 0;
    e->exit_group.error_code = e->args[0];

    bpf_ringbuf_submit(e, 0);
    return 0;
}
