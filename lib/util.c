
#include "fuse_config.h"

#ifdef HAVE_PTHREAD_SETNAME_NP
#define _GNU_SOURCE
#include <pthread.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <errno.h>

#include "util.h"

int libfuse_strtol(const char *str, long *res)
{
	char *endptr;
	int base = 10;
	long val;

	errno = 0;

	if (!str)
		return -EINVAL;

	val = strtol(str, &endptr, base);

	if (errno)
	       return -errno;

	if (endptr == str || *endptr != '\0')
		return -EINVAL;

	*res = val;
	return 0;
}

void fuse_set_thread_name(unsigned long tid, const char *name)
{
#ifdef HAVE_PTHREAD_SETNAME_NP
	pthread_setname_np(tid, name);
#else
	(void)tid;
	(void)name;
#endif
}
