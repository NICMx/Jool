#ifndef _JOOL_COMMON_XLAT_H
#define _JOOL_COMMON_XLAT_H

#include <linux/types.h>
#ifndef __KERNEL__
	#include <stdbool.h>
#endif

#define XLAT_VERSION_MAJOR 3
#define XLAT_VERSION_MINOR 3
#define XLAT_VERSION_REV 2
#define XLAT_VERSION_DEV 10

/** See http://stackoverflow.com/questions/195975 */
#define STR_VALUE(arg) #arg
#define VALUE_TO_STR(name) STR_VALUE(name)
#define XLAT_VERSION_STR \
	VALUE_TO_STR(XLAT_VERSION_MAJOR) "." \
	VALUE_TO_STR(XLAT_VERSION_MINOR) "." \
	VALUE_TO_STR(XLAT_VERSION_REV)

static inline unsigned int xlat_version(void)
{
	return (XLAT_VERSION_MAJOR << 24)
			| (XLAT_VERSION_MINOR << 16)
			| (XLAT_VERSION_REV << 8)
			| XLAT_VERSION_DEV;
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
