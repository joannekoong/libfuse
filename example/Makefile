# Makefile
CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
APP_NAME := famfs
.PHONY: all clean
all: $(APP_NAME).skel.h
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
$(APP_NAME).bpf.o: $(APP_NAME).bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
$(APP_NAME).skel.h: $(APP_NAME).bpf.o
	$(BPFTOOL) gen skeleton $< > $@
clean:
	rm -f *.o *.skel.h vmlinux.h
