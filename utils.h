#ifndef __UTILS_H__
#define __UTILS_H__

#include <linux/version.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define ERANGE 34

static __always_inline
long
bpf_get_path(char *kpath, const char *upath)
{
    const size_t size = PATH_SIZE;
    
    long ret = bpf_probe_read_user_str(kpath, size, upath);
    if (ret < 0) {
        bpf_printk("bpf_get_path failed %ld for reading from %px", ret, upath);
    } else if (ret == 0 || ret == size) {
        ret = -ERANGE;
    }
    return ret;
}

static __always_inline
long
bpf_get_xattr_name(char *xname, const char *uname)
{
    const size_t size = XNAME_SIZE;

    long ret = bpf_probe_read_user_str(xname, size, uname);

    if (ret < 0) {
        bpf_printk("bpf_get_xattr_name failed");
    } else if (ret == 0 || ret == size) {
        ret = -ERANGE;
    }
    return ret;
}

static __always_inline
long
bpf_get_xattr_value(u8 *to, size_t size, void *ufrom)
{
    long ret = bpf_probe_read_user_str(
            to, size > XVALUE_SIZE ? XVALUE_SIZE : size, ufrom);
    if (ret < 0) {
        bpf_printk("bpf_get_xattr_value failed");
    } else if (ret == 0 || ret == size) {
        ret = -ERANGE;
    }
    return ret;
}


static __always_inline
const struct file *
bpf_get_task_file(struct task_struct *task, unsigned fd_number)
{
// #if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
//     return bpf_fd_lookup(fd, task, 0);
// #else
    // race condition may be here, but BPF rejects spin_locks
    struct files_struct *files = BPF_CORE_READ(task, files);
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) {
        return 0;
    }
    struct file **fd = BPF_CORE_READ(fdt, fd);
    unsigned max_fds = BPF_CORE_READ(fdt, max_fds);
    if (fd_number >= max_fds) {
        return 0;
    }

    struct file *file = 0;
    bpf_probe_read_kernel(&file, sizeof file, &fd[fd_number]);

    return file;
// #endif
}

static __always_inline
const struct inode *
bpf_file_inode(const struct file *file)
{
    return BPF_CORE_READ(file, f_inode);
}

#endif
