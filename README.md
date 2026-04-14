# fusesnoop
libbpf tool to track syscalls into the kernel FUSE driver using BPF CO-RE with modern probe types (fprobes). Currently supports open(),openat(),openat2().

## Requirements
Very minimal userspace requirements because of CO-RE; libbpf is statically linked. Kernel 5.10+ with the following config options enabled:

...

## Sources

- [https://origin.kernel.org/doc/html/latest/bpf/](https://origin.kernel.org/doc/html/latest/bpf/)
- [https://docs.ebpf.io](https://docs.ebpf.io)
- [https://libbpf.readthedocs.io/en/latest/](https://libbpf.readthedocs.io/en/latest/)
- [Opensnoop and other tool examples that ship with BCC](https://github.com/iovisor/bcc)
- Learning eBPF book and [examples](https://github.com/lizrice/learning-ebpf)
- [https://nakryiko.com/posts/bpf-ringbuf/](https://nakryiko.com/posts/bpf-ringbuf/)
- [https://nakryiko.com/posts/bpf-core-reference-guide/](https://nakryiko.com/posts/bpf-core-reference-guide/)
