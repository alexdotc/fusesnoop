#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "shared.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));

} perfbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct data_t);

} heap SEC(".maps");

SEC("kprobe/fuse_open_common")
int BPF_KPROBE(fusesnoop, struct inode *inode, struct file *file) {
    struct data_t *event;
    int key_zero = 0;
    event = bpf_map_lookup_elem(&heap, &key_zero); // weird function signature where we need to provide a pointer to a key. Hm, I guess if the keys aren't ints it makes sense
    if (!event)
        return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
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

    bpf_perf_event_output(ctx, &perfbuf, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL"; // need this to call some bpf helpers, the compiler will even complain otherwise
