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

#define JOOL_VERSION_MAJOR 3
#define JOOL_VERSION_MINOR 3
#define JOOL_VERSION_REV 1
#define JOOL_VERSION_DEV 14

#define STR(s) #s
#define JOOL_VERSION_STR \
	STR(JOOL_VERSION_MAJOR) "." \
	STR(JOOL_VERSION_MINOR) "." \
	STR(JOOL_VERSION_REV)

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

static inline unsigned int version_8to32(unsigned int major, unsigned int minor,
		unsigned int revision, unsigned int development)
{
	return (major << 24) | (minor << 16) | (revision << 8) | development;
}

static inline unsigned int jool_version(void)
{
	return version_8to32(JOOL_VERSION_MAJOR,
			JOOL_VERSION_MINOR,
			JOOL_VERSION_REV,
			JOOL_VERSION_DEV);
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
