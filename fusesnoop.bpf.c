#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "shared.h"

#define RINGBUF_MAX_SIZE 1024 * 1024 // 1M

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_MAX_SIZE);

} ringbuf SEC(".maps");

SEC("fexit/fuse_open_common")
int BPF_PROG(fusesnoop, struct inode *inode, struct file *file, bool isdir, long ret) {
    struct data_t *event = bpf_ringbuf_reserve(&ringbuf, sizeof(struct data_t), 0);
    if (!event)
        return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->ret = ret;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // fullpath
    struct dentry *me = BPF_CORE_READ(file, f_path.dentry);
    struct dentry *parent = NULL;
    uint8_t *bufptr = event->filename.pathbuf;
    int *depth = &event->filename.depth;
    for (uint8_t curr_depth = 0; curr_depth < PATH_MAX_DEPTH; curr_depth++) {
        bpf_probe_read_kernel(bufptr, PATH_FILENAME_MAX_LEN, BPF_CORE_READ(me, d_name.name));
        parent = BPF_CORE_READ(me, d_parent);
        if (me == parent) // fs root
            break;
        me = parent;
        bufptr += PATH_FILENAME_MAX_LEN;
        (*depth)++;
    }

    bpf_ringbuf_submit(event, 0); // *dst, userspace notification flags
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL"; // need this to call some bpf helpers, the compiler will even complain otherwise
