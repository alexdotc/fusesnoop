#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "shared.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); // 1M

} ringbuf SEC(".maps");

SEC("fexit/fuse_open_common")
int BPF_PROG(fusesnoop, struct inode *inode, struct file *file, bool isdir, long ret)
{
    struct data_t *event = bpf_ringbuf_reserve(&ringbuf, sizeof(struct data_t), 0);
    if (!event)
        return 0;

    //struct dentry *me;
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->ret = ret;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    const uint8_t *filename = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), filename);
    bpf_ringbuf_submit(event, 0); // userspace notification flags
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL"; // need this to call some bpf helpers, the compiler will even complain otherwise
