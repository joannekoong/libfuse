/*
 * FUSE: Filesystem in Userspace
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE
 */

#ifndef FUSE_EXAMPLE_PASSTHROUGH_HELPERS_H_
#define FUSE_EXAMPLE_PASSTHROUGH_HELPERS_H_

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef __FreeBSD__
#include <sys/socket.h>
#include <sys/un.h>
#endif

static inline int do_fallocate(int fd, int mode, off_t offset, off_t length)
{
#ifdef HAVE_FALLOCATE
	if (fallocate(fd, mode, offset, length) == -1)
		return -errno;
	return 0;
#else  // HAVE_FALLOCATE

#ifdef HAVE_POSIX_FALLOCATE
	if (mode == 0)
		return -posix_fallocate(fd, offset, length);
#endif

#ifdef HAVE_FSPACECTL
	// 0x3 == FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE
	if (mode == 0x3) {
		struct spacectl_range sr;

		sr.r_offset = offset;
		sr.r_len = length;
		if (fspacectl(fd, SPACECTL_DEALLOC, &sr, 0, NULL) == -1)
			return -errno;
		return 0;
	}
#endif

	return -EOPNOTSUPP;
#endif  // HAVE_FALLOCATE
}

/*
 * Creates files on the underlying file system in response to a FUSE_MKNOD
 * operation
 */
static inline int mknod_wrapper(int dirfd, const char *path, const char *link,
	int mode, dev_t rdev)
{
	int res;

	if (S_ISREG(mode)) {
		res = openat(dirfd, path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISDIR(mode)) {
		res = mkdirat(dirfd, path, mode);
	} else if (S_ISLNK(mode) && link != NULL) {
		res = symlinkat(link, dirfd, path);
	} else if (S_ISFIFO(mode)) {
		res = mkfifoat(dirfd, path, mode);
#ifdef __FreeBSD__
	} else if (S_ISSOCK(mode)) {
		struct sockaddr_un su;
		int fd;

		if (strlen(path) >= sizeof(su.sun_path)) {
			errno = ENAMETOOLONG;
			return -1;
		}
		fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd >= 0) {
			/*
			 * We must bind the socket to the underlying file
			 * system to create the socket file, even though
			 * we'll never listen on this socket.
			 */
			su.sun_family = AF_UNIX;
			strncpy(su.sun_path, path, sizeof(su.sun_path));
			res = bindat(dirfd, fd, (struct sockaddr*)&su,
				sizeof(su));
			if (res == 0)
				close(fd);
		} else {
			res = -1;
		}
#endif
	} else {
		res = mknodat(dirfd, path, mode, rdev);
	}

	return res;
}

#endif  // FUSE_PASSTHROUGH_HELPERS_H_
