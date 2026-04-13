#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "fusesnoop.skel.h"
#include "shared.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level >= LIBBPF_DEBUG)
        return 0;

    return vfprintf(stderr, format, args);
}

void write_filepath(struct fullpath *pathbuf){
    // might need to be error checked a little more carefully
    // start from the last position, which should always be the root node (fs root)
    int path_depth = pathbuf->depth;
    uint8_t *bufptr = (pathbuf->pathbuf) + (path_depth * PATH_FILENAME_MAX_LEN);
    for (int curr_depth = path_depth; curr_depth >= 0; curr_depth--) {
        if (path_depth == 0) {
            printf("/");
            break;
        }
        if (*bufptr == '/')
            goto decrement_bufptr;
        printf("/%s", bufptr);
        decrement_bufptr:
        bufptr -= PATH_FILENAME_MAX_LEN;
    }
    printf("\n");
}

int print_event(void *ctx, void *data, size_t data_sz) {
    struct data_t *event = data;
    printf("%-10d %-6d %-6ld %-16s", event->pid, event->uid, event->ret, event->comm);
    write_filepath(&event->filename);
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
        err = ring_buffer__poll(ringbuf, 100);
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
