TARGET = fusesnoop

BPF_OBJ = ${TARGET:=.bpf.o}
USER_C = ${TARGET:=.c}
USER_SKEL = ${TARGET:=.skel.h}

all: $(TARGET) $(BPF_OBJ)
.PHONY: all

$(TARGET): $(USER_C) $(USER_SKEL) 
	gcc -Wall -o $(TARGET) $(USER_C) -l:libbpf.a -lelf -lz

%.bpf.o: %.bpf.c vmlinux.h
	clang -target bpf -Wall -O2 -g -o $@ -c $<
	llvm-strip -g $@

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	- rm $(TARGET)
	- rm $(BPF_OBJ)
	- rm $(USER_SKEL)
	- rm vmlinux.h
