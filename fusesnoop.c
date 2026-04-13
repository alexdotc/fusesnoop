#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "fusesnoop.skel.h"
#include "shared.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level >= LIBBPF_DEBUG)
        return 0;

    return vfprintf(stderr, format, args);
}

int print_event(void *ctx, void *data, size_t data_sz) {
    struct data_t *event = data;
    printf("%-10d %-6d %-6ld %-16s %s\n", event->pid, event->uid, event->ret, event->comm, event->filename);
    return 0;
}

int main() {
    struct fusesnoop_bpf *skel;
    int err;
    struct ring_buffer *ringbuf = NULL;

    libbpf_set_print(libbpf_print_fn);

    skel = fusesnoop_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = fusesnoop_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        fusesnoop_bpf__destroy(skel);
        return 1;
    }

    ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), print_event, NULL, NULL);
    if (!ringbuf) {
       	err = -1;
       	fprintf(stderr, "Failed to create ring buffer\n");
       	fusesnoop_bpf__destroy(skel);
        return 1;
    }

    printf("Fusesnoop\nTrace open events on FUSE filesystems...\n");
    printf("%-10s %-6s %-6s %-16s %s\n", "PID", "UID", "RC", "COMM", "PATH");
    
    while (1) {
        err = ring_buffer__poll(ringbuf, 500);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(ringbuf);
    fusesnoop_bpf__destroy(skel);
    return -err;
}
