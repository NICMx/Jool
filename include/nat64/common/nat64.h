#ifndef _JOOL_COMMON_NAT64_H
#define _JOOL_COMMON_NAT64_H

/**
 * @file
 * Extremely general global stuff.
 *
 * @author Alberto Leiva
 */

#ifdef STATEFUL
#define MODULE_NAME "NAT64 Jool"
#else
#define MODULE_NAME "SIIT Jool"
#endif

/**
 * These defines are read in from dkms.conf. If you change their syntax or
 * relocate them, please make sure to also update dkms.conf accordingly.
 */
#define JOOL_VERSION_MAJOR 3
#define JOOL_VERSION_MINOR 3
#define JOOL_VERSION_REV 3
#define JOOL_VERSION_DEV 0

/** See http://stackoverflow.com/questions/195975 */
#define STR_VALUE(arg) #arg
#define VALUE_TO_STR(name) STR_VALUE(name)
#define JOOL_VERSION_STR \
	VALUE_TO_STR(JOOL_VERSION_MAJOR) "." \
	VALUE_TO_STR(JOOL_VERSION_MINOR) "." \
	VALUE_TO_STR(JOOL_VERSION_REV)

/**
 * Please tend to use nat64_is_stateful() instead of the STATEFUL macro.
 * By using the function version, your compilations will be aware of the alternate mode so you will
 * not accidentally wreck it. Also #ifdefs look hairy.
 *
 * TODO (fine) #include bool?
 */
static inline int nat64_is_stateful(void)
{
#ifdef STATEFUL
	return 1;
#else
	return 0;
#endif
}

static inline int nat64_is_stateless(void)
{
	return !nat64_is_stateful();
}

/**
 * Eh. These arguments are actually intended as "const u8" (which would remove
 * the need for the "0xFFU"s), but I don't want to include types in such a basic
 * file just for this one function. I dunno.
 */
static inline unsigned int version_8to32(const unsigned int major,
		const unsigned int minor, const unsigned int revision,
		const unsigned int development)
{
	return ((major & 0xFFU) << 24) | ((minor & 0xFFU) << 16)
			| ((revision & 0xFFU) << 8) | (development & 0xFFU);
}

static inline unsigned int jool_version(void)
{
	return version_8to32(JOOL_VERSION_MAJOR, JOOL_VERSION_MINOR,
			JOOL_VERSION_REV, JOOL_VERSION_DEV);
}

#define NF_IP_PRI_JOOL (NF_IP_PRI_NAT_DST + 25)
#define NF_IP6_PRI_JOOL (NF_IP6_PRI_NAT_DST + 25)

static inline int is_logtime_enabled(void)
{
#ifdef BENCHMARK
	return 1;
#else
	return 0;
#endif
}

#endif /* _JOOL_COMMON_NAT64_H */
