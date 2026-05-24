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

struct syscall_args {
    __u64 args[6];
};

struct smack_snapshot {
    __u32 flags;
    char obj[SMACK_LABEL_SIZE];
    char exec[SMACK_LABEL_SIZE];
    char mmap[SMACK_LABEL_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct smack_snapshot);
} smack_scratch_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct syscall_args);
} args_map SEC(".maps");

extern struct lsm_blob_sizes smack_blob_sizes __ksym __weak;

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct smack_snapshot);
} mkdir_smack_map SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct smack_snapshot);
} chmod_smack_map SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct smack_snapshot);
} chown_smack_map SEC(".maps");

struct execve_data {
    char   pathname[PATH_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct execve_data);
} execve_map SEC(".maps");

struct dentry_call_ctx {
    struct dentry *dentry;
    int depth;
};

struct old_dentry_call_ctx {
    struct dentry *old_dentry;
    int depth;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct dentry_call_ctx);
} unlink_ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct smack_snapshot);
} unlink_smack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct dentry_call_ctx);
} rmdir_ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct smack_snapshot);
} rmdir_smack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct old_dentry_call_ctx);
} link_ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct smack_snapshot);
} link_smack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct dentry_call_ctx);
} symlink_ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct smack_snapshot);
} symlink_smack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct smack_snapshot);
} rename_smack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct smack_snapshot);
} access_smack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, u8);
} access_pending_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct dentry_call_ctx);
} getxattr_ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct smack_snapshot);
} getxattr_smack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct dentry_call_ctx);
} setxattr_ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, struct smack_snapshot);
} setxattr_smack_map SEC(".maps");

static __always_inline const struct monitor_config *monitor_cfg(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&config_map, &key);
}

static __always_inline __u64 smack_blob_sizes_addr(void)
{
    const struct monitor_config *cfg = monitor_cfg();

    if (!cfg) {
        return 0;
    }
    return cfg->smack_blob_sizes_addr;
}

static __always_inline int smack_inode_offset(void)
{
    __u64 base;
    const void *ptr;
    int offset = -1;

    base = smack_blob_sizes_addr();
    if (base) {
        ptr = (const void *)(unsigned long)(base +
              __builtin_offsetof(struct lsm_blob_sizes, lbs_inode));
        if (bpf_probe_read_kernel(&offset, sizeof(offset), ptr) == 0) {
            return offset;
        }
    }

    if (bpf_probe_read_kernel(&offset, sizeof(offset), &smack_blob_sizes.lbs_inode) < 0) {
        return -1;
    }
    return offset;
}

static __always_inline int smack_cred_offset(void)
{
    __u64 base;
    const void *ptr;
    int offset = -1;

    base = smack_blob_sizes_addr();
    if (base) {
        ptr = (const void *)(unsigned long)(base +
              __builtin_offsetof(struct lsm_blob_sizes, lbs_cred));
        if (bpf_probe_read_kernel(&offset, sizeof(offset), ptr) == 0) {
            return offset;
        }
    }

    if (bpf_probe_read_kernel(&offset, sizeof(offset), &smack_blob_sizes.lbs_cred) < 0) {
        return -1;
    }
    return offset;
}

static __always_inline void read_smack_label(struct smack_known *skp,
                                             char *dst,
                                             __u32 dst_size)
{
    char *label;

    if (dst_size > 0) {
        dst[0] = '\0';
    }
    if (!skp) {
        return;
    }
    label = BPF_CORE_READ(skp, smk_known);
    if (!label) {
        return;
    }
    if (bpf_probe_read_kernel_str(dst, dst_size, label) < 0) {
        dst[0] = '\0';
    }
}

static __always_inline int capture_inode_smack(struct inode *inode,
                                               struct smack_snapshot *out)
{
    int offset;
    void *blob;
    struct inode_smack *isp;
    struct smack_known *obj;
    struct smack_known *exec;
    struct smack_known *mmap;

    if (!inode || !out) {
        return 0;
    }
    out->flags = 0;
    out->obj[0] = '\0';
    out->exec[0] = '\0';
    out->mmap[0] = '\0';
    offset = smack_inode_offset();
    if (offset < 0) {
        return 0;
    }
    blob = BPF_CORE_READ(inode, i_security);
    if (!blob) {
        return 0;
    }

    isp = (struct inode_smack *)((char *)blob + offset);
    out->flags = BPF_CORE_READ(isp, smk_flags);

    obj = BPF_CORE_READ(isp, smk_inode);
    exec = BPF_CORE_READ(isp, smk_task);
    mmap = BPF_CORE_READ(isp, smk_mmap);

    read_smack_label(obj, out->obj, sizeof(out->obj));
    read_smack_label(exec, out->exec, sizeof(out->exec));
    read_smack_label(mmap, out->mmap, sizeof(out->mmap));

    return 1;
}

static __always_inline void apply_smack_snapshot(struct syscall_event *e,
                                                 const struct smack_snapshot *snap)
{
    if (!e || !snap) {
        return;
    }

    e->smack_flags = snap->flags;
    __builtin_memcpy(e->smack_obj, snap->obj, sizeof(e->smack_obj));
    __builtin_memcpy(e->smack_exec, snap->exec, sizeof(e->smack_exec));
    __builtin_memcpy(e->smack_mmap, snap->mmap, sizeof(e->smack_mmap));
}

static __always_inline struct smack_snapshot *smack_scratch_get(void);

static __always_inline void apply_smack_from_map(struct syscall_event *e,
                                                 void *map,
                                                 u64 id,
                                                 int apply_condition)
{
    struct smack_snapshot *snap;

    snap = bpf_map_lookup_elem(map, &id);
    if (!snap) {
        return;
    }
    if (apply_condition) {
        apply_smack_snapshot(e, snap);
    }
    bpf_map_delete_elem(map, &id);
}

static __always_inline void capture_inode_smack_once(void *map,
                                                     u64 id,
                                                     struct inode *inode)
{
    struct smack_snapshot *snap;
    struct smack_snapshot *existing;

    existing = bpf_map_lookup_elem(map, &id);
    if (existing || !inode) {
        return;
    }
    snap = smack_scratch_get();
    if (!snap || !capture_inode_smack(inode, snap)) {
        return;
    }
    bpf_map_update_elem(map, &id, snap, BPF_ANY);
}

static __always_inline struct smack_snapshot *smack_scratch_get(void)
{
    u32 key = 0;
    struct smack_snapshot *snap;

    snap = bpf_map_lookup_elem(&smack_scratch_map, &key);
    if (!snap) {
        return 0;
    }
    return snap;
}

static __always_inline void init_event_smack(struct syscall_event *e)
{
    e->smack_subj[0] = '\0';
    e->smack_obj[0] = '\0';
    e->smack_exec[0] = '\0';
    e->smack_mmap[0] = '\0';
    e->smack_flags = 0;
}

static __always_inline void fill_inode_smack(struct syscall_event *e,
                                             struct inode *inode)
{
    struct smack_snapshot *snap;

    snap = smack_scratch_get();
    if (!snap) {
        return;
    }
    if (capture_inode_smack(inode, snap)) {
        apply_smack_snapshot(e, snap);
    }
}

static __always_inline void fill_fd_smack(struct syscall_event *e, int fd)
{
    struct task_struct *task;
    const struct file *file;
    const struct inode *inode;

    task = (struct task_struct *)bpf_get_current_task();
    file = bpf_get_task_file(task, fd);
    if (!file) {
        return;
    }
    inode = bpf_file_inode(file);
    if (!inode) {
        return;
    }

    fill_inode_smack(e, (struct inode *)inode);
}

static __always_inline void fill_subject_smack(struct syscall_event *e)
{
    int offset;
    struct task_struct *task;
    const struct cred *cred;
    void *blob;
    struct task_smack *tsp;
    struct smack_known *task_label;

    e->smack_subj[0] = '\0';
    offset = smack_cred_offset();
    if (offset < 0) {
        return;
    }

    task = (struct task_struct *)bpf_get_current_task();
    cred = BPF_CORE_READ(task, cred);
    if (!cred) {
        return;
    }
    blob = BPF_CORE_READ(cred, security);
    if (!blob) {
        return;
    }

    tsp = (struct task_smack *)((char *)blob + offset);
    task_label = BPF_CORE_READ(tsp, smk_task);
    read_smack_label(task_label, e->smack_subj, sizeof(e->smack_subj));
}


static __always_inline int should_monitor(void)
{
    const struct monitor_config *cfg = monitor_cfg();

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

    struct chown_ctx *cctx;
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
    struct smack_snapshot *snap = smack_scratch_get();
    if (snap && capture_inode_smack(inode, snap)) {
        bpf_map_update_elem(&chmod_smack_map, &id, snap, BPF_ANY);
    }

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
    struct smack_snapshot *snap = smack_scratch_get();
    if (snap && capture_inode_smack(inode, snap)) {
        bpf_map_update_elem(&chown_smack_map, &id, snap, BPF_ANY);
    }

CLEANUP:
    bpf_map_delete_elem(&chown_map, &id);
    return 0;
}

static __always_inline
int
save_syscall_args(struct trace_event_raw_sys_enter *ctx)
{
    u64 key;
    struct syscall_args args = {};
    long ret;

    if (!should_monitor()) {
        return 0;
    }

    BPF_CORE_READ_INTO(&args.args, ctx, args);
    key = bpf_get_current_pid_tgid();

    if ((ret = bpf_map_update_elem(&args_map, &key, &args, BPF_ANY)) < 0) {
        bpf_printk("update elem returns %ld", ret);
    }

    return 1;
}

static __always_inline void access_pending_start(void)
{
    u64 id = bpf_get_current_pid_tgid();
    u8 one = 1;
    bpf_map_update_elem(&access_pending_map, &id, &one, BPF_ANY);
    bpf_map_delete_elem(&access_smack_map, &id);
}

static __always_inline void access_pending_stop(void)
{
    u64 id = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&access_pending_map, &id);
    bpf_map_delete_elem(&access_smack_map, &id);
}

static __always_inline
struct syscall_event *
read_syscall_args(struct trace_event_raw_sys_exit *ctx)
{
    u64 key;
    u64 pid_tgid;
    u64 uid_gid;
    struct syscall_args *args;
    struct syscall_event *e;

    key = bpf_get_current_pid_tgid();
    if (!(args = bpf_map_lookup_elem(&args_map, &key))) {
        return 0;
    }
    bpf_map_delete_elem(&args_map, &key);
    if (!should_monitor()) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&events, sizeof *e, 0);
    if (!e) {
        bpf_printk("ringbuffer overflow");
        return 0;
    }
    init_event_smack(e);

    e->ts = bpf_ktime_get_ns();

    pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & ((1uLL << 32) - 1);
    e->tgid = pid_tgid >> 32;

    uid_gid = bpf_get_current_uid_gid();
    e->euid = uid_gid & ((1uLL << 32) - 1);
    e->egid = uid_gid >> 32;

    bpf_get_current_comm(&e->comm, sizeof e->comm);
    
    e->syscall_nr = ctx->id;
    __builtin_memcpy(e->args, args->args, sizeof e->args);
    fill_subject_smack(e);

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
    if (!file) {
        goto END;
    }
    const struct inode *i = bpf_file_inode(file);
    if (!i) {
        goto END;
    }

    e->open.uid = BPF_CORE_READ(i, i_uid).val;
    e->open.gid = BPF_CORE_READ(i, i_gid).val;
    e->open.ino = BPF_CORE_READ(i, i_ino);
    e->open.perms = BPF_CORE_READ(i, i_mode);
    fill_inode_smack(e, (struct inode *)i);

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
    if (!file) {
        goto END;
    }
    const struct inode *i = bpf_file_inode(file);
    if (!i) {
        goto END;
    }

    e->openat.uid = BPF_CORE_READ(i, i_uid).val;
    e->openat.gid = BPF_CORE_READ(i, i_gid).val;
    e->openat.ino = BPF_CORE_READ(i, i_ino);
    e->openat.perms = BPF_CORE_READ(i, i_mode);
    fill_inode_smack(e, (struct inode *)i);

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
    if (!file) {
        goto END;
    }
    const struct inode *i = bpf_file_inode(file);
    if (!i) {
        goto END;
    }

    e->creat.uid = BPF_CORE_READ(i, i_uid).val;
    e->creat.gid = BPF_CORE_READ(i, i_gid).val;
    e->creat.ino = BPF_CORE_READ(i, i_ino);
    e->creat.perms = BPF_CORE_READ(i, i_mode);
    fill_inode_smack(e, (struct inode *)i);

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
    struct dentry *dentry = dentryp->dentry;
    bpf_map_delete_elem(&mkdir_dentry, &id);
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
    struct smack_snapshot *snap = smack_scratch_get();
    if (snap && capture_inode_smack(inode, snap)) {
        bpf_map_update_elem(&mkdir_smack_map, &id, snap, BPF_ANY);
    }

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
        bpf_map_delete_elem(&mkdir_smack_map, &pid_tgid);
        goto END;
    }

    e->mkdir.uid   = data->i_uid.val;
    e->mkdir.gid   = data->i_gid.val;
    e->mkdir.ino   = data->i_ino;
    e->mkdir.perms = data->i_mode;
    struct smack_snapshot *snap = bpf_map_lookup_elem(&mkdir_smack_map, &pid_tgid);
    if (snap) {
        apply_smack_snapshot(e, snap);
    }

    bpf_map_delete_elem(&mkdir_map, &pid_tgid);
    bpf_map_delete_elem(&mkdir_smack_map, &pid_tgid);

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
        bpf_map_delete_elem(&mkdir_smack_map, &pid_tgid);
        goto END;
    }

    e->mkdirat.uid   = data->i_uid.val;
    e->mkdirat.gid   = data->i_gid.val;
    e->mkdirat.ino   = data->i_ino;
    e->mkdirat.perms = data->i_mode;
    struct smack_snapshot *snap = bpf_map_lookup_elem(&mkdir_smack_map, &pid_tgid);
    if (snap) {
        apply_smack_snapshot(e, snap);
    }

    bpf_map_delete_elem(&mkdir_map, &pid_tgid);
    bpf_map_delete_elem(&mkdir_smack_map, &pid_tgid);

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
    if (e->ret == 0) {
        fill_fd_smack(e, e->fchdir.fd);
    }
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
        bpf_map_delete_elem(&chmod_smack_map, &pid_tgid);
        goto END;
    }

    e->chmod.perms = data->i_mode;
    struct smack_snapshot *snap = bpf_map_lookup_elem(&chmod_smack_map, &pid_tgid);
    if (snap) {
        apply_smack_snapshot(e, snap);
    }

    bpf_map_delete_elem(&chmod_data_map, &pid_tgid);
    bpf_map_delete_elem(&chmod_smack_map, &pid_tgid);

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
        bpf_map_delete_elem(&chmod_smack_map, &pid_tgid);
        fill_fd_smack(e, e->fchmod.fd);
        goto END;
    }

    e->fchmod.perms = data->i_mode;
    struct smack_snapshot *snap = bpf_map_lookup_elem(&chmod_smack_map, &pid_tgid);
    if (snap) {
        apply_smack_snapshot(e, snap);
    }
    bpf_map_delete_elem(&chmod_data_map, &pid_tgid);
    bpf_map_delete_elem(&chmod_smack_map, &pid_tgid);

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
        bpf_map_delete_elem(&chown_smack_map, &pid_tgid);
        goto END;
    }

    e->chown.perms = data->i_mode;
    struct smack_snapshot *snap = bpf_map_lookup_elem(&chown_smack_map, &pid_tgid);
    if (snap) {
        apply_smack_snapshot(e, snap);
    }

    bpf_map_delete_elem(&chown_data_map, &pid_tgid);
    bpf_map_delete_elem(&chown_smack_map, &pid_tgid);

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
        bpf_printk("chown without saved data");
        bpf_map_delete_elem(&chown_smack_map, &pid_tgid);
        fill_fd_smack(e, e->fchown.fd);
        goto END;
    }

    e->fchown.perms = data->i_mode;
    struct smack_snapshot *snap = bpf_map_lookup_elem(&chown_smack_map, &pid_tgid);
    if (snap) {
        apply_smack_snapshot(e, snap);
    }
    bpf_map_delete_elem(&chown_data_map, &pid_tgid);
    bpf_map_delete_elem(&chown_smack_map, &pid_tgid);

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

SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(handle_security_inode_unlink,
               struct inode *dir,
               struct dentry *dentry)
{
    u64 id;
    struct inode *inode;
    struct smack_snapshot *snap;
    struct smack_snapshot *existing;

    if (!should_monitor()) {
        return 0;
    }

    id = bpf_get_current_pid_tgid();
    existing = bpf_map_lookup_elem(&unlink_smack_map, &id);
    if (existing) {
        return 0;
    }
    inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) {
        return 0;
    }
    snap = smack_scratch_get();
    if (!snap || !capture_inode_smack(inode, snap)) {
        return 0;
    }
    bpf_map_update_elem(&unlink_smack_map, &id, snap, BPF_ANY);
    return 0;
}

SEC("kprobe/security_path_unlink")
int BPF_KPROBE(handle_security_path_unlink,
               const struct path *dir,
               struct dentry *dentry)
{
    u64 id;
    struct inode *inode;
    struct smack_snapshot *snap;
    struct smack_snapshot *existing;

    if (!should_monitor()) {
        return 0;
    }

    id = bpf_get_current_pid_tgid();
    existing = bpf_map_lookup_elem(&unlink_smack_map, &id);
    if (existing) {
        return 0;
    }
    inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) {
        return 0;
    }
    snap = smack_scratch_get();
    if (!snap || !capture_inode_smack(inode, snap)) {
        return 0;
    }
    bpf_map_update_elem(&unlink_smack_map, &id, snap, BPF_ANY);
    return 0;
}

SEC("kprobe/vfs_unlink")
int BPF_KPROBE(handle_vfs_unlink,
               struct mnt_idmap *idmap,
               struct inode *dir,
               struct dentry *dentry,
               struct inode **delegated_inode)
{
    struct inode *inode;
    struct smack_snapshot *snap;

    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    struct dentry_call_ctx *ctxp;

    ctxp = bpf_map_lookup_elem(&unlink_ctx_map, &id);
    if (!ctxp) {
        struct dentry_call_ctx ctx_data = {};
        struct smack_snapshot *existing;
        ctx_data.dentry = dentry;
        bpf_map_update_elem(&unlink_ctx_map, &id, &ctx_data, BPF_ANY);

        /* Capture object label at call entry while dentry->d_inode is still stable. */
        existing = bpf_map_lookup_elem(&unlink_smack_map, &id);
        if (existing) {
            return 0;
        }
        inode = BPF_CORE_READ(dentry, d_inode);
        if (!inode) {
            return 0;
        }
        snap = smack_scratch_get();
        if (!snap || !capture_inode_smack(inode, snap)) {
            return 0;
        }
        bpf_map_update_elem(&unlink_smack_map, &id, snap, BPF_ANY);
    } else {
        ++ctxp->depth;
        bpf_map_update_elem(&unlink_ctx_map, &id, ctxp, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(handle_vfs_unlink_ret)
{
    u64 id;
    long ret;
    struct dentry_call_ctx *ctxp;

    if (!should_monitor()) {
        return 0;
    }

    id = bpf_get_current_pid_tgid();
    ctxp = bpf_map_lookup_elem(&unlink_ctx_map, &id);
    if (!ctxp) {
        return 0;
    }
    if (ctxp->depth > 0) {
        --ctxp->depth;
        bpf_map_update_elem(&unlink_ctx_map, &id, ctxp, BPF_ANY);
        return 0;
    }

    bpf_map_delete_elem(&unlink_ctx_map, &id);

    ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        bpf_map_delete_elem(&unlink_smack_map, &id);
        return 0;
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_unlink")
int trace_exit_unlink(struct trace_event_raw_sys_exit *ctx)
{
    u64 id;
    struct smack_snapshot *snap;
    struct syscall_event *e;

    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->unlink.pathname, (char *)e->args[0]);
    id = bpf_get_current_pid_tgid();
    snap = bpf_map_lookup_elem(&unlink_smack_map, &id);
    if (snap) {
        if (e->ret == 0) {
            apply_smack_snapshot(e, snap);
        }
        bpf_map_delete_elem(&unlink_smack_map, &id);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int trace_enter_rmdir(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("kprobe/security_inode_rmdir")
int BPF_KPROBE(handle_security_inode_rmdir,
               struct inode *dir,
               struct dentry *dentry)
{
    u64 id;
    struct inode *inode;
    struct smack_snapshot *snap;
    struct smack_snapshot *existing;

    if (!should_monitor()) {
        return 0;
    }

    id = bpf_get_current_pid_tgid();
    existing = bpf_map_lookup_elem(&rmdir_smack_map, &id);
    if (existing) {
        return 0;
    }
    inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) {
        return 0;
    }
    snap = smack_scratch_get();
    if (!snap || !capture_inode_smack(inode, snap)) {
        return 0;
    }
    bpf_map_update_elem(&rmdir_smack_map, &id, snap, BPF_ANY);
    return 0;
}

SEC("kprobe/security_path_rmdir")
int BPF_KPROBE(handle_security_path_rmdir,
               const struct path *dir,
               struct dentry *dentry)
{
    u64 id;
    struct inode *inode;
    struct smack_snapshot *snap;
    struct smack_snapshot *existing;

    if (!should_monitor()) {
        return 0;
    }

    id = bpf_get_current_pid_tgid();
    existing = bpf_map_lookup_elem(&rmdir_smack_map, &id);
    if (existing) {
        return 0;
    }
    inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) {
        return 0;
    }
    snap = smack_scratch_get();
    if (!snap || !capture_inode_smack(inode, snap)) {
        return 0;
    }
    bpf_map_update_elem(&rmdir_smack_map, &id, snap, BPF_ANY);
    return 0;
}

SEC("kprobe/vfs_rmdir")
int BPF_KPROBE(handle_vfs_rmdir,
               struct mnt_idmap *idmap,
               struct inode *dir,
               struct dentry *dentry)
{
    struct inode *inode;
    struct smack_snapshot *snap;

    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    struct dentry_call_ctx *ctxp;

    ctxp = bpf_map_lookup_elem(&rmdir_ctx_map, &id);
    if (!ctxp) {
        struct dentry_call_ctx ctx_data = {};
        struct smack_snapshot *existing;
        ctx_data.dentry = dentry;
        bpf_map_update_elem(&rmdir_ctx_map, &id, &ctx_data, BPF_ANY);

        /* Capture object label at call entry while dentry->d_inode is still stable. */
        existing = bpf_map_lookup_elem(&rmdir_smack_map, &id);
        if (existing) {
            return 0;
        }
        inode = BPF_CORE_READ(dentry, d_inode);
        if (!inode) {
            return 0;
        }
        snap = smack_scratch_get();
        if (!snap || !capture_inode_smack(inode, snap)) {
            return 0;
        }
        bpf_map_update_elem(&rmdir_smack_map, &id, snap, BPF_ANY);
    } else {
        ++ctxp->depth;
        bpf_map_update_elem(&rmdir_ctx_map, &id, ctxp, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/vfs_rmdir")
int BPF_KRETPROBE(handle_vfs_rmdir_ret)
{
    u64 id;
    long ret;
    struct dentry_call_ctx *ctxp;

    if (!should_monitor()) {
        return 0;
    }

    id = bpf_get_current_pid_tgid();
    ctxp = bpf_map_lookup_elem(&rmdir_ctx_map, &id);
    if (!ctxp) {
        return 0;
    }
    if (ctxp->depth > 0) {
        --ctxp->depth;
        bpf_map_update_elem(&rmdir_ctx_map, &id, ctxp, BPF_ANY);
        return 0;
    }

    bpf_map_delete_elem(&rmdir_ctx_map, &id);

    ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        bpf_map_delete_elem(&rmdir_smack_map, &id);
        return 0;
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_rmdir")
int trace_exit_rmdir(struct trace_event_raw_sys_exit *ctx)
{
    u64 id;
    struct smack_snapshot *snap;
    struct syscall_event *e;

    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->rmdir.pathname, (char *)e->args[0]);
    id = bpf_get_current_pid_tgid();
    snap = bpf_map_lookup_elem(&rmdir_smack_map, &id);
    if (snap) {
        if (e->ret == 0) {
            apply_smack_snapshot(e, snap);
        }
        bpf_map_delete_elem(&rmdir_smack_map, &id);
    }

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
    if (e->ret >= 0) {
        fill_fd_smack(e, e->getdents.fd);
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents64")
int trace_enter_getdents64(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int trace_exit_getdents64(struct trace_event_raw_sys_exit *ctx)
{
    struct syscall_event *e;
    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->getdents64.fd = e->args[0];
    if (e->ret >= 0) {
        fill_fd_smack(e, e->getdents64.fd);
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_access")
int trace_enter_access(struct trace_event_raw_sys_enter *ctx)
{
    if (!save_syscall_args(ctx)) {
        return 0;
    }
    access_pending_start();
    return 1;
}

SEC("tracepoint/syscalls/sys_exit_access")
int trace_exit_access(struct trace_event_raw_sys_exit *ctx)
{
    u64 id;
    struct syscall_event *e;

    if (!(e = read_syscall_args(ctx))) {
        access_pending_stop();
        return 0;
    }

    bpf_get_path(e->access.pathname, (char *)e->args[0]);
    e->access.mode = e->args[1];

    id = bpf_get_current_pid_tgid();
    apply_smack_from_map(e, &access_smack_map, id, e->ret == 0);

    bpf_ringbuf_submit(e, 0);
    access_pending_stop();
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_faccessat")
int trace_enter_faccessat(struct trace_event_raw_sys_enter *ctx)
{
    if (!save_syscall_args(ctx)) {
        return 0;
    }
    access_pending_start();
    return 1;
}

SEC("tracepoint/syscalls/sys_exit_faccessat")
int trace_exit_faccessat(struct trace_event_raw_sys_exit *ctx)
{
    u64 id;
    struct syscall_event *e;

    if (!(e = read_syscall_args(ctx))) {
        access_pending_stop();
        return 0;
    }

    e->faccessat.dfd = e->args[0];
    bpf_get_path(e->faccessat.pathname, (char *)e->args[1]);
    e->faccessat.mode = e->args[2];
    e->faccessat.flags = e->args[3];

    id = bpf_get_current_pid_tgid();
    apply_smack_from_map(e, &access_smack_map, id, e->ret == 0);

    bpf_ringbuf_submit(e, 0);
    access_pending_stop();
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_faccessat2")
int trace_enter_faccessat2(struct trace_event_raw_sys_enter *ctx)
{
    if (!save_syscall_args(ctx)) {
        return 0;
    }
    access_pending_start();
    return 1;
}

SEC("tracepoint/syscalls/sys_exit_faccessat2")
int trace_exit_faccessat2(struct trace_event_raw_sys_exit *ctx)
{
    u64 id;
    struct syscall_event *e;

    if (!(e = read_syscall_args(ctx))) {
        access_pending_stop();
        return 0;
    }

    e->faccessat2.dfd = e->args[0];
    bpf_get_path(e->faccessat2.pathname, (char *)e->args[1]);
    e->faccessat2.mode = e->args[2];
    e->faccessat2.flags = e->args[3];

    id = bpf_get_current_pid_tgid();
    apply_smack_from_map(e, &access_smack_map, id, e->ret == 0);

    bpf_ringbuf_submit(e, 0);
    access_pending_stop();
    return 0;
}

SEC("kprobe/security_inode_permission")
int BPF_KPROBE(handle_security_inode_permission,
               struct mnt_idmap *idmap,
               struct inode *inode,
               int mask)
{
    u64 id;
    u8 *pending;

    if (!should_monitor()) {
        return 0;
    }

    id = bpf_get_current_pid_tgid();
    pending = bpf_map_lookup_elem(&access_pending_map, &id);
    if (!pending) {
        return 0;
    }
    capture_inode_smack_once(&access_smack_map, id, inode);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_link")
int trace_enter_link(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("kprobe/vfs_link")
int BPF_KPROBE(handle_vfs_link,
               struct dentry *old_dentry,
               struct mnt_idmap *idmap,
               struct inode *dir,
               struct dentry *new_dentry,
               struct inode **delegated_inode)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    struct old_dentry_call_ctx *ctxp;

    ctxp = bpf_map_lookup_elem(&link_ctx_map, &id);
    if (!ctxp) {
        struct old_dentry_call_ctx ctx_data = {};
        ctx_data.old_dentry = old_dentry;
        bpf_map_update_elem(&link_ctx_map, &id, &ctx_data, BPF_ANY);
    } else {
        ++ctxp->depth;
        bpf_map_update_elem(&link_ctx_map, &id, ctxp, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/vfs_link")
int BPF_KRETPROBE(handle_vfs_link_ret)
{
    u64 id;
    long ret;
    struct old_dentry_call_ctx *ctxp;
    struct dentry *old_dentry;
    struct inode *inode;
    struct smack_snapshot *snap;

    if (!should_monitor()) {
        return 0;
    }

    id = bpf_get_current_pid_tgid();
    ctxp = bpf_map_lookup_elem(&link_ctx_map, &id);
    if (!ctxp) {
        return 0;
    }
    if (ctxp->depth > 0) {
        --ctxp->depth;
        bpf_map_update_elem(&link_ctx_map, &id, ctxp, BPF_ANY);
        return 0;
    }

    old_dentry = ctxp->old_dentry;
    bpf_map_delete_elem(&link_ctx_map, &id);

    ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        return 0;
    }

    inode = BPF_CORE_READ(old_dentry, d_inode);
    if (!inode) {
        return 0;
    }
    snap = smack_scratch_get();
    if (!snap || !capture_inode_smack(inode, snap)) {
        return 0;
    }
    bpf_map_update_elem(&link_smack_map, &id, snap, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_link")
int trace_exit_link(struct trace_event_raw_sys_exit *ctx)
{
    u64 id;
    struct syscall_event *e;

    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->link.oldname, (char *)e->args[0]);
    bpf_get_path(e->link.newname, (char *)e->args[1]);
    id = bpf_get_current_pid_tgid();
    apply_smack_from_map(e, &link_smack_map, id, e->ret == 0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int trace_enter_linkat(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_linkat")
int trace_exit_linkat(struct trace_event_raw_sys_exit *ctx)
{
    u64 id;
    struct syscall_event *e;

    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->linkat.olddfd = e->args[0];
    bpf_get_path(e->linkat.oldname, (char *)e->args[1]);
    e->linkat.newdfd = e->args[2];
    bpf_get_path(e->linkat.newname, (char *)e->args[3]);
    e->linkat.flags = e->args[4];
    id = bpf_get_current_pid_tgid();
    apply_smack_from_map(e, &link_smack_map, id, e->ret == 0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int trace_enter_symlink(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("kprobe/vfs_symlink")
int BPF_KPROBE(handle_vfs_symlink,
               struct mnt_idmap *idmap,
               struct inode *dir,
               struct dentry *dentry,
               const char *oldname)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    struct dentry_call_ctx *ctxp;

    ctxp = bpf_map_lookup_elem(&symlink_ctx_map, &id);
    if (!ctxp) {
        struct dentry_call_ctx ctx_data = {};
        ctx_data.dentry = dentry;
        bpf_map_update_elem(&symlink_ctx_map, &id, &ctx_data, BPF_ANY);
    } else {
        ++ctxp->depth;
        bpf_map_update_elem(&symlink_ctx_map, &id, ctxp, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/vfs_symlink")
int BPF_KRETPROBE(handle_vfs_symlink_ret)
{
    u64 id;
    long ret;
    struct dentry_call_ctx *ctxp;
    struct dentry *dentry;
    struct inode *inode;
    struct smack_snapshot *snap;

    if (!should_monitor()) {
        return 0;
    }

    id = bpf_get_current_pid_tgid();
    ctxp = bpf_map_lookup_elem(&symlink_ctx_map, &id);
    if (!ctxp) {
        return 0;
    }
    if (ctxp->depth > 0) {
        --ctxp->depth;
        bpf_map_update_elem(&symlink_ctx_map, &id, ctxp, BPF_ANY);
        return 0;
    }

    dentry = ctxp->dentry;
    bpf_map_delete_elem(&symlink_ctx_map, &id);

    ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        return 0;
    }

    inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) {
        return 0;
    }
    snap = smack_scratch_get();
    if (!snap || !capture_inode_smack(inode, snap)) {
        return 0;
    }
    bpf_map_update_elem(&symlink_smack_map, &id, snap, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_symlink")
int trace_exit_symlink(struct trace_event_raw_sys_exit *ctx)
{
    u64 id;
    struct syscall_event *e;

    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->symlink.oldname, (char *)e->args[0]);
    bpf_get_path(e->symlink.newname, (char *)e->args[1]);
    id = bpf_get_current_pid_tgid();
    apply_smack_from_map(e, &symlink_smack_map, id, e->ret == 0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_unlinkat")
int trace_exit_unlinkat(struct trace_event_raw_sys_exit *ctx)
{
    u64 id;
    struct syscall_event *e;

    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->unlinkat.dfd = e->args[0];
    bpf_get_path(e->unlinkat.pathname, (char *)e->args[1]);
    e->unlinkat.flags = e->args[2];
    id = bpf_get_current_pid_tgid();
    apply_smack_from_map(e, &unlink_smack_map, id, e->ret == 0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/security_path_rename")
int BPF_KPROBE(handle_security_path_rename,
               const struct path *old_dir,
               struct dentry *old_dentry,
               const struct path *new_dir,
               struct dentry *new_dentry,
               unsigned int flags)
{
    u64 id;
    struct inode *inode;

    if (!should_monitor()) {
        return 0;
    }

    id = bpf_get_current_pid_tgid();
    inode = BPF_CORE_READ(old_dentry, d_inode);
    capture_inode_smack_once(&rename_smack_map, id, inode);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_enter_rename(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_rename")
int trace_exit_rename(struct trace_event_raw_sys_exit *ctx)
{
    u64 id;
    struct syscall_event *e;

    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->rename.oldname, (char *)e->args[0]);
    bpf_get_path(e->rename.newname, (char *)e->args[1]);
    id = bpf_get_current_pid_tgid();
    apply_smack_from_map(e, &rename_smack_map, id, e->ret == 0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_enter_renameat(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_renameat")
int trace_exit_renameat(struct trace_event_raw_sys_exit *ctx)
{
    u64 id;
    struct syscall_event *e;

    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->renameat.olddfd = e->args[0];
    bpf_get_path(e->renameat.oldname, (char *)e->args[1]);
    e->renameat.newdfd = e->args[2];
    bpf_get_path(e->renameat.newname, (char *)e->args[3]);
    id = bpf_get_current_pid_tgid();
    apply_smack_from_map(e, &rename_smack_map, id, e->ret == 0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_enter_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("tracepoint/syscalls/sys_exit_renameat2")
int trace_exit_renameat2(struct trace_event_raw_sys_exit *ctx)
{
    u64 id;
    struct syscall_event *e;

    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    e->renameat2.olddfd = e->args[0];
    bpf_get_path(e->renameat2.oldname, (char *)e->args[1]);
    e->renameat2.newdfd = e->args[2];
    bpf_get_path(e->renameat2.newname, (char *)e->args[3]);
    e->renameat2.flags = e->args[4];
    id = bpf_get_current_pid_tgid();
    apply_smack_from_map(e, &rename_smack_map, id, e->ret == 0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getxattr")
int trace_enter_getxattr(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("kprobe/vfs_getxattr")
int BPF_KPROBE(handle_vfs_getxattr,
               struct mnt_idmap *idmap,
               struct dentry *dentry,
               const char *name,
               void *value,
               size_t size)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    struct dentry_call_ctx *ctxp;

    ctxp = bpf_map_lookup_elem(&getxattr_ctx_map, &id);
    if (!ctxp) {
        struct dentry_call_ctx ctx_data = {};
        ctx_data.dentry = dentry;
        bpf_map_update_elem(&getxattr_ctx_map, &id, &ctx_data, BPF_ANY);
    } else {
        ++ctxp->depth;
        bpf_map_update_elem(&getxattr_ctx_map, &id, ctxp, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/vfs_getxattr")
int BPF_KRETPROBE(handle_vfs_getxattr_ret)
{
    u64 id;
    long ret;
    struct dentry_call_ctx *ctxp;
    struct dentry *dentry;
    struct inode *inode;
    struct smack_snapshot *snap;

    if (!should_monitor()) {
        return 0;
    }

    id = bpf_get_current_pid_tgid();
    ctxp = bpf_map_lookup_elem(&getxattr_ctx_map, &id);
    if (!ctxp) {
        return 0;
    }
    if (ctxp->depth > 0) {
        --ctxp->depth;
        bpf_map_update_elem(&getxattr_ctx_map, &id, ctxp, BPF_ANY);
        return 0;
    }

    dentry = ctxp->dentry;
    bpf_map_delete_elem(&getxattr_ctx_map, &id);

    ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        return 0;
    }

    inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) {
        return 0;
    }
    snap = smack_scratch_get();
    if (!snap || !capture_inode_smack(inode, snap)) {
        return 0;
    }
    bpf_map_update_elem(&getxattr_smack_map, &id, snap, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getxattr")
int trace_exit_getxattr(struct trace_event_raw_sys_exit *ctx)
{
    u64 id;
    struct syscall_event *e;

    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->getxattr.pathname, (char *)e->args[0]);
    bpf_get_xattr_name(e->getxattr.name, (char *)e->args[1]);
    e->getxattr.addr = (void *)e->args[2];
    e->getxattr.size = e->args[3];
    bpf_get_xattr_value(e->getxattr.value, e->getxattr.size, e->getxattr.addr);
    id = bpf_get_current_pid_tgid();
    apply_smack_from_map(e, &getxattr_smack_map, id, e->ret >= 0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setxattr")
int trace_enter_setxattr(struct trace_event_raw_sys_enter *ctx)
{
    return save_syscall_args(ctx);
}

SEC("kprobe/vfs_setxattr")
int BPF_KPROBE(handle_vfs_setxattr,
               struct mnt_idmap *idmap,
               struct dentry *dentry,
               const char *name,
               const void *value,
               size_t size,
               int flags)
{
    if (!should_monitor()) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    struct dentry_call_ctx *ctxp;

    ctxp = bpf_map_lookup_elem(&setxattr_ctx_map, &id);
    if (!ctxp) {
        struct dentry_call_ctx ctx_data = {};
        ctx_data.dentry = dentry;
        bpf_map_update_elem(&setxattr_ctx_map, &id, &ctx_data, BPF_ANY);
    } else {
        ++ctxp->depth;
        bpf_map_update_elem(&setxattr_ctx_map, &id, ctxp, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/vfs_setxattr")
int BPF_KRETPROBE(handle_vfs_setxattr_ret)
{
    u64 id;
    long ret;
    struct dentry_call_ctx *ctxp;
    struct dentry *dentry;
    struct inode *inode;
    struct smack_snapshot *snap;

    if (!should_monitor()) {
        return 0;
    }

    id = bpf_get_current_pid_tgid();
    ctxp = bpf_map_lookup_elem(&setxattr_ctx_map, &id);
    if (!ctxp) {
        return 0;
    }
    if (ctxp->depth > 0) {
        --ctxp->depth;
        bpf_map_update_elem(&setxattr_ctx_map, &id, ctxp, BPF_ANY);
        return 0;
    }

    dentry = ctxp->dentry;
    bpf_map_delete_elem(&setxattr_ctx_map, &id);

    ret = PT_REGS_RC(ctx);
    if (ret < 0) {
        return 0;
    }

    inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) {
        return 0;
    }
    snap = smack_scratch_get();
    if (!snap || !capture_inode_smack(inode, snap)) {
        return 0;
    }
    bpf_map_update_elem(&setxattr_smack_map, &id, snap, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_setxattr")
int trace_exit_setxattr(struct trace_event_raw_sys_exit *ctx)
{
    u64 id;
    struct syscall_event *e;

    if (!(e = read_syscall_args(ctx))) {
        return 0;
    }

    bpf_get_path(e->setxattr.pathname, (char *)e->args[0]);
    bpf_get_xattr_name(e->setxattr.name, (char *)e->args[1]);
    e->setxattr.size = e->args[3];
    e->setxattr.flags = e->args[4];
    bpf_get_xattr_value(e->setxattr.value, e->setxattr.size, (uint8_t *)e->args[2]);
    id = bpf_get_current_pid_tgid();
    apply_smack_from_map(e, &setxattr_smack_map, id, e->ret == 0);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    // comm at enter is the old process name (before exec replaces the image),
    // so save args unconditionally; the exit handler filters by the new comm.
    u64 key = bpf_get_current_pid_tgid();
    struct syscall_args args = {};
    long ret;
    BPF_CORE_READ_INTO(&args.args, ctx, args);
    if ((ret = bpf_map_update_elem(&args_map, &key, &args, BPF_ANY)) < 0) {
        bpf_printk("update elem returns %ld", ret);
    }
    return 1;
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

        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct mm_struct *mm = BPF_CORE_READ(task, mm);
        struct file *exe = BPF_CORE_READ(mm, exe_file);
        struct inode *inode = BPF_CORE_READ(exe, f_inode);
        fill_inode_smack(e, inode);
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
    init_event_smack(e);

    e->ts = bpf_ktime_get_ns();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & ((1uLL << 32) - 1);
    e->tgid = pid_tgid >> 32;
    u64 uid_gid = bpf_get_current_uid_gid();
    e->euid = uid_gid & ((1uLL << 32) - 1);
    e->egid = uid_gid >> 32;

    bpf_get_current_comm(&e->comm, sizeof e->comm);

    e->syscall_nr = ctx->id;
    struct syscall_args args = {};
    BPF_CORE_READ_INTO(&args.args, ctx, args);
     __builtin_memcpy(e->args, &args.args, sizeof e->args);
    fill_subject_smack(e);

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
    init_event_smack(e);

    e->ts = bpf_ktime_get_ns();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & ((1uLL << 32) - 1);
    e->tgid = pid_tgid >> 32;
    u64 uid_gid = bpf_get_current_uid_gid();
    e->euid = uid_gid & ((1uLL << 32) - 1);
    e->egid = uid_gid >> 32;

    bpf_get_current_comm(&e->comm, sizeof e->comm);

    e->syscall_nr = ctx->id;
    struct syscall_args args = {};
    BPF_CORE_READ_INTO(&args.args, ctx, args);
     __builtin_memcpy(e->args, &args.args, sizeof e->args);
    fill_subject_smack(e);

    e->ret = 0;
    e->exit_group.error_code = e->args[0];

    bpf_ringbuf_submit(e, 0);
    return 0;
}
