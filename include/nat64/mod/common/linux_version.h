#ifndef _JOOL_COMMON_LINUX_VERSION_H
#define _JOOL_COMMON_LINUX_VERSION_H

#include <linux/version.h>

/*
 * A bunch of code has to be compiled differently depending on kernel version.
 * RHEL kernels, however, do not define the LINUX_VERSION_CODE macro correctly.
 *
 * LINUX_VERSION_CODE is therefore not always a good solution; use these macros
 * instead.
 */

#ifndef RHEL_RELEASE_VERSION
/**
 * Don't mind this one; it's intended to prevent the macros below from expanding
 * "RHEL_RELEASE_VERSION(rhela, rhelb)" into "0(rhela, rhelb)".
 * :p
 */
#define RHEL_RELEASE_VERSION(a, b) 0
#endif

#define LINUX_VERSION_AT_LEAST(a, b, c, ra, rb) \
	((defined RHEL_RELEASE_CODE \
			&& RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(ra, rb)) \
	|| LINUX_VERSION_CODE >= KERNEL_VERSION(a, b, c))

#define LINUX_VERSION_LOWER_THAN(a, b, c, ra, rb) \
	(defined RHEL_RELEASE_CODE \
			&& RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(ra, rb)) \
	|| LINUX_VERSION_CODE < KERNEL_VERSION(a, b, c)

#endif
