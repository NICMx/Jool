#ifndef _JOOL_COMMON_XLAT_H
#define _JOOL_COMMON_XLAT_H

#include <linux/types.h>
#ifndef __KERNEL__
	#include <stdbool.h>
#endif

/**
 * These defines are read in from dkms.conf. If you change their syntax or
 * relocate them, please make sure to also update dkms.conf accordingly.
 */
#define JOOL_VERSION_MAJOR 3
#define JOOL_VERSION_MINOR 5
#define JOOL_VERSION_REV 4
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

/**
 * xlat_is_siit - Is this translator a Stateless IP/ICMP Translator?
 * Otherwise it's a NAT64.
 */
bool xlat_is_siit(void);

/**
 * xlat_is_nat64 - Is this translator a Stateful NAT64 Translator?
 * Otherwise it's a SIIT.
 */
static inline bool xlat_is_nat64(void)
{
	return !xlat_is_siit();
}

const char *xlat_get_name(void);

#endif /* _JOOL_COMMON_XLAT_H */
