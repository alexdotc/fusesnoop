# fusesnoop
eBPF libbpf tool to track syscalls into the kernel FUSE driver using BPF CO-RE with modern probe types (fprobes). Currently supports open(),openat(),openat2().

## Requirements to Run
Very minimal userspace requirements because of CO-RE; libbpf is statically linked. This has been developed and tested on
Rocky Linux 9.7, kernel 5.14 (with backports).kernel 5.14 (with backports). But any kernel around 5.10ish with the
following config options enabled should work (you don't actually need all of these, but this is everything relevant
to this BPF tracing program):

```
# Comments my own
# Core functionality
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y # enable bpf(2)
CONFIG_BPF_EVENTS=y # enable attaching BPF programs to kprobes and tracepoints
CONFIG_FPROBE=y # enable support for fentry/fexit trampolines
CONFIG_TRACEPOINTS=y 
CONFIG_HAVE_SYSCALL_TRACEPOINTS=y
# JIT instead of interpreter
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_ARCH_WANT_DEFAULT_BPF_JIT=y
CONFIG_BPF_JIT_DEFAULT_ON=y # default JIT on (sysctl)
# Security
CONFIG_BPF_JIT_ALWAYS_ON=y # prevent switching JIT off at runtime (sysctl), remove BPF interpreter entirely
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y # only root can load bpf programs, other users can't use it even in a limited capacity (certain prog types etc.)
# BTF/CO-RE related (for portability across kernels)
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
CONFIG_PAHOLE_HAS_SPLIT_BTF=y
## Requirements to Build
```

## Sources

- [https://origin.kernel.org/doc/html/latest/bpf/](https://origin.kernel.org/doc/html/latest/bpf/)
- [https://docs.ebpf.io](https://docs.ebpf.io)
- [https://libbpf.readthedocs.io/en/latest/](https://libbpf.readthedocs.io/en/latest/)
- [Opensnoop and other tool examples that ship with BCC](https://github.com/iovisor/bcc)
- Learning eBPF book and [examples](https://github.com/lizrice/learning-ebpf)
- [https://nakryiko.com/posts/bpf-ringbuf/](https://nakryiko.com/posts/bpf-ringbuf/)
- [https://nakryiko.com/posts/bpf-core-reference-guide/](https://nakryiko.com/posts/bpf-core-reference-guide/)
