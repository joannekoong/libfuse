#ifndef FAMFS_COMMON_H
#define FAMFS_COMMON_H

#ifndef __bpf__
#include <linux/types.h>
#endif

#define FAMFS_FMAP_MAX 32768
#define FAMFS_MAX_EXTENTS 32
#define FAMFS_MAX_STRIPS  16

#define IOMAP_MAPPED 2

enum fuse_famfs_file_type {
        FUSE_FAMFS_FILE_REG,
        FUSE_FAMFS_FILE_SUPERBLOCK,
        FUSE_FAMFS_FILE_LOG,
};

enum famfs_ext_type {
        FUSE_FAMFS_EXT_SIMPLE = 0,
        FUSE_FAMFS_EXT_INTERLEAVE = 1,
};

struct famfs_meta_simple_ext_bpf {
	__u64 dev_index;
	__u64 ext_offset;
	__u64 ext_len;
};

struct famfs_meta_interleaved_ext_bpf {
	__u64 fie_nstrips;
	__u64 fie_chunk_size;
	__u64 fie_nbytes;
	struct famfs_meta_simple_ext_bpf ie_strips[FAMFS_MAX_STRIPS]; /* inlined */
};

struct famfs_file_meta {
	__u8   error;
	__u32  file_type;
	__u64  file_size;
	__u32  fm_extent_type;
	__u64  dev_bitmap;
	union {
		struct {
			__u64 fm_nextents;
			struct famfs_meta_simple_ext_bpf se[FAMFS_MAX_EXTENTS];
		};
		struct {
			__u64 fm_niext;
			struct famfs_meta_interleaved_ext_bpf ie[FAMFS_MAX_EXTENTS];
		};
	};
};

#endif /* FAMFS_COMMON_H */
