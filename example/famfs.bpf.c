#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

#include "famfs_common.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define IS_ALIGNED(x, a) (((x) & ((typeof(x))(a) - 1)) == 0)

struct fuse_iomap_io {
        __u64 offset;        /* file offset of mapping, bytes */
        __u64 length;        /* length of mapping, bytes */
        __u64 addr;          /* disk offset of mapping, bytes */
        __u16 type;          /* FUSE_IOMAP_TYPE_* */
        __u16 flags;         /* FUSE_IOMAP_F_* */
        __u32 dev;           /* device cookie */
	__u64 id; 	     /* for dax devices */
};

struct fuse_bpf_ops {
        int (*iomap_begin)(__u64 nodeid, loff_t, loff_t, unsigned int, struct fuse_iomap_io *);
        char name[16];
	int dev_fd;
};

/*
 * Hashmap going from "nodeid -> struct famfs_file_meta"
 *
 * On receiving the OPEN, the server populates the map
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FAMFS_FMAP_MAX);
	__type(key, __u64); 	/* node_id */
	__type(value, struct famfs_file_meta);
} famfs_meta_hashmap SEC(".maps");

/*
 * Implement the callbacks as BPF programs
 */
SEC("struct_ops/iomap_begin")
int BPF_PROG(bpf_iomap_begin, __u64 nodeid, loff_t file_offset,
             loff_t length, unsigned int flags, struct fuse_iomap_io *out)
{
	bpf_printk("fuse iomap_begin: inode=%llu pos=%llu len=%llu flags=%u\n",
		   nodeid, file_offset, length, flags);

	struct famfs_file_meta *meta;
	__u64 local_offset = file_offset;

	if (!out)
		return -EIO;

	meta = bpf_map_lookup_elem(&famfs_meta_hashmap, &nodeid);
	if (!meta) {
		bpf_printk("famfs_file_meta not found for inode=%lu\n", nodeid);
		return -EIO;
	}

	if (meta->fm_extent_type == FUSE_FAMFS_EXT_SIMPLE) {
		__u64 fm_nextents = meta->fm_nextents;
		int i;

		if (fm_nextents > FAMFS_MAX_EXTENTS)
			fm_nextents = FAMFS_MAX_EXTENTS;

		for (i = 0; i < fm_nextents; i++) {
			__u64 dax_ext_offset = meta->se[i].ext_offset;
			__u64 dax_ext_len = meta->se[i].ext_len;
			__u64 daxdev_idx = meta->se[i].dev_index;

			/* local_offset is the offset minus the size of extents skipped
			 * so far; If local_offset < dax_ext_len, the data of interest
			 * starts in this extent
			 */
			if (local_offset < dax_ext_len) {
				__u64 ext_len_remainder = dax_ext_len - local_offset;

				/*
				 * OK, we found the file metadata extent where this
				 * data begins
				 * @local_offset      - The offset within the current
				 *                      extent
				 * @ext_len_remainder - Remaining length of ext after
				 *                      skipping local_offset
				 * Outputs:
				 * iomap->addr:   the offset within the dax device where
				 *                the  data starts
				 * iomap->offset: the file offset
				 * iomap->length: the valid length resolved here
				 */
				out->offset = file_offset;
				out->addr = dax_ext_offset + local_offset;
				out->length = MIN(length, ext_len_remainder);
				out->type = IOMAP_MAPPED;
				out->id = daxdev_idx;
				out->flags = flags;

				bpf_printk("found extent\n");
				return 0;
			}
			local_offset -= dax_ext_len; /* Get ready for the next extent */
		}
	} else {
		__u64 fm_niext = meta->fm_niext;
		int i;

		if (fm_niext > FAMFS_MAX_EXTENTS)
			fm_niext = FAMFS_MAX_EXTENTS;

		for (i = 0; i < fm_niext; i++) {
		    struct famfs_meta_interleaved_ext_bpf *fei = &meta->ie[i];
		    __u64 chunk_size = fei->fie_chunk_size;
		    __u64 nstrips = fei->fie_nstrips;
		    __u64 ext_size = MIN(fei->fie_nbytes, meta->file_size);

		    if (ext_size == 0)
			    return -EIO;

		    /* Is the data in this striped extent? */
		    if (local_offset < ext_size) {
			    __u64 chunk_num       = local_offset / chunk_size;
			    __u64 chunk_offset    = local_offset % chunk_size;
			    __u64 chunk_remainder = chunk_size - chunk_offset;
			    __u64 stripe_num      = chunk_num / nstrips;
			    __u64 strip_num       = chunk_num % nstrips;
			    __u64 strip_offset    = chunk_offset + (stripe_num * chunk_size);
			    __u64 strip_dax_ofs;
			    __u64 strip_devidx;

			    if (strip_num >= FAMFS_MAX_STRIPS)
				    return -EIO;
			    strip_dax_ofs = fei->ie_strips[strip_num].ext_offset;
			    strip_devidx = fei->ie_strips[strip_num].dev_index;

			    out->addr = strip_dax_ofs + strip_offset;
			    out->offset = file_offset;
			    out->length = MIN(length, chunk_remainder);
			    out->id = strip_devidx;
			    out->type = IOMAP_MAPPED;
			    out->flags = flags;

			    bpf_printk("found interleaved extent\n");
			    return 0;
		    }
		    local_offset -= ext_size; /* offset is beyond this striped extent */
		}
	}

	return -EIO; /* not found */
}

SEC(".struct_ops.link")
struct fuse_bpf_ops fuse_ops = {
    .iomap_begin = (void *)bpf_iomap_begin,
    .name = "fuse_iomap_bpf",
    .dev_fd = -1, /* server will fill this out before attaching */
};

char LICENSE[] SEC("license") = "GPL";
