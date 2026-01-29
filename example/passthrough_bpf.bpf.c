#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct fuse_bpf_ops {
        int (*iomap_begin)(struct inode *, loff_t, loff_t, unsigned int);
        char name[16];
};

/* copied from darrick's iomap patchset */
struct fuse_iomap_io {
        uint64_t offset;        /* file offset of mapping, bytes */
        uint64_t length;        /* length of mapping, bytes */
        uint64_t addr;          /* disk offset of mapping, bytes */
        uint16_t type;          /* FUSE_IOMAP_TYPE_* */
        uint16_t flags;         /* FUSE_IOMAP_F_* */
        uint32_t dev;           /* device cookie */
};

/*
 * Implement the callbacks as BPF programs
 */
SEC("struct_ops/iomap_begin")
int BPF_PROG(bpf_iomap_begin, struct inode *inode, loff_t pos,
             loff_t length, unsigned int flags, struct fuse_iomap_io *out)
{
    bpf_printk("fuse iomap_begin: inode=%lx pos=%lld len=%lld flags=%u\n",
               (unsigned long)inode, pos, length, flags);

    if (out)
	out->offset = 999;
    
   return 0; 
}

SEC(".struct_ops.link")
struct fuse_bpf_ops fuse_ops = {
    .iomap_begin = (void *)bpf_iomap_begin,
    .name = "fuse_iomap_bpf",
};
