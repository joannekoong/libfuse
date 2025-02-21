// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

struct fuse_in_header {
        uint32_t        len;
        uint32_t        opcode;
        uint64_t        unique;
        uint64_t        nodeid;
        uint32_t        uid;
        uint32_t        gid;
        uint32_t        pid;
        uint16_t        total_extlen; /* length of extensions in 8byte units */
        uint16_t        padding;
};

SEC("usdt")
int BPF_USDT(usdt_attach, uint32_t opcode, uint32_t unique)
{
	struct fuse_in_header in;
	bpf_printk("USDT attach\n");
	bpf_printk("request opcode=%u, unique=%u\n", opcode, unique);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
