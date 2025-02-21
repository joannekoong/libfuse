// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

SEC("usdt")
int BPF_USDT(usdt_attach, uint32_t opcode, uint32_t unique)
{
	bpf_printk("USDT attach\n");
	bpf_printk("request opcode=%u, unique=%u\n", opcode, unique);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
