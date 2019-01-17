#ifndef _JOOL_COMMON_XLAT_H
#define _JOOL_COMMON_XLAT_H

#include <linux/types.h>
#ifndef __KERNEL__
	#include <stdbool.h>
#endif

#define JOOL_LICENSE "GPL v2"

/**
 * These defines are read in from dkms.conf. If you change their syntax or
 * relocate them, please make sure to also update dkms.conf accordingly.
 */
#define JOOL_VERSION_MAJOR 4
#define JOOL_VERSION_MINOR 0
#define JOOL_VERSION_REV 0
#define JOOL_VERSION_DEV 0

/** See http://stackoverflow.com/questions/195975 */
#define STR_VALUE(arg) #arg
#define VALUE_TO_STR(name) STR_VALUE(name)
#define JOOL_VERSION_STR \
	VALUE_TO_STR(JOOL_VERSION_MAJOR) "." \
	VALUE_TO_STR(JOOL_VERSION_MINOR) "." \
	VALUE_TO_STR(JOOL_VERSION_REV) "." \
	VALUE_TO_STR(JOOL_VERSION_DEV)

static inline unsigned int xlat_version(void)
{
	return (JOOL_VERSION_MAJOR << 24)
			| (JOOL_VERSION_MINOR << 16)
			| (JOOL_VERSION_REV << 8)
			| JOOL_VERSION_DEV;
}

/** Bitwise or'd XT_* constants below. */
typedef int xlator_type;

#define XT_SIIT (1 << 0)
#define XT_NAT64 (1 << 1)
#define XT_BOTH (XT_SIIT | XT_NAT64)

/**
 * Returns either XT_SIIT or XT_NAT64.
 */
int xlat_type(void);

#define xlat_is_siit() (xlat_type() & XT_SIIT)
#define xlat_is_nat64() (xlat_type() & XT_NAT64)

const char *xlat_get_name(void);

#endif /* _JOOL_COMMON_XLAT_H */
