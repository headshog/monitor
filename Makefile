.DELETE_ON_ERROR:

CLANG ?= clang
BPFTOOL ?= bpftool

ifeq ($(shell command -v $(CLANG) 2>/dev/null),)
$(error clang not found in PATH)
endif

ifeq ($(shell command -v $(BPFTOOL) 2>/dev/null),)
$(error bpftool not found in PATH)
endif

ARCH ?= $(shell uname -m)
ifeq ($(ARCH),x86_64)
BPF_ARCH := x86
else ifeq ($(ARCH),aarch64)
BPF_ARCH := arm64
else ifeq ($(ARCH),arm64)
BPF_ARCH := arm64
else
$(error unsupported architecture $(ARCH); set BPF_ARCH manually)
endif

load: monitor
	./monitor load

unload: monitor
	./monitor unload

monitor: monitor.c syscall_monitor.h syscall_monitor.skel.h
	$(CLANG) monitor.c -g -Wall -Werror -I/usr/local/include -L/usr/local/lib -Wl,-rpath,/usr/local/lib -lbpf -lelf -lz -o $@

syscall_monitor.bpf.o: syscall_monitor.bpf.c utils.h vmlinux.h
	$(CLANG) -O2 -Wall -Werror -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -fno-merge-all-constants -c $< -o $@

syscall_monitor.skel.h: syscall_monitor.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

vmlinux.h: /sys/kernel/btf/vmlinux
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -rf *.o syscall_monitor.skel.h vmlinux.h monitor

.PHONY: clean load unload
