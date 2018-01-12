#include "rfc6052.h"

static __be32 __addr_6to4(const struct in6_addr *addr,
		int q1, int q2, int q3, int q4)
{
	return cpu_to_be32((addr->s6_addr[q1] << 24)
			| (addr->s6_addr[q2] << 16)
			| (addr->s6_addr[q3] << 8)
			| (addr->s6_addr[q4]));
}

int rfc6052_6to4(struct xlation *state,
		const struct in6_addr *src,
		struct in_addr *dst)
{
	struct ipv6_prefix *prefix = &state->GLOBAL.pool6;

	switch (prefix->len) {
	case 96: /* First because it's the most common one, I guess. */
		dst->s_addr = src->s6_addr32[3];
		return 0;
	case 32:
		dst->s_addr = src->s6_addr32[1];
		return 0;
	case 40:
		dst->s_addr = __addr_6to4(src, 5, 6, 7, 9);
		return 0;
	case 48:
		dst->s_addr = __addr_6to4(src, 6, 7, 9, 10);
		return 0;
	case 56:
		dst->s_addr = __addr_6to4(src, 7, 9, 10, 11);
		return 0;
	case 64:
		dst->s_addr = __addr_6to4(src, 9, 10, 11, 12);
		return 0;
	case 0:
		log_debug("pool6 hasn't been configured.");
		return esrch(state, JOOL_MIB_POOL6_NULL);
	}

	/*
	 * Critical because enforcing valid prefixes is global's responsibility,
	 * not ours.
	 */
	WARN(true, "Prefix has an invalid length: %u.", prefix->len);
	return einval(state, JOOL_MIB_UNKNOWN6);
}

static void __addr_4to6(const struct in_addr *src, struct in6_addr *dst,
		int q1, int q2, int q3, int q4)
{
	__u32 addr4 = be32_to_cpu(src->s_addr);

	dst->s6_addr[q1] =  addr4 >> 24;
	dst->s6_addr[q2] = (addr4 >> 16) & (__u8)0xFFu;
	dst->s6_addr[q3] = (addr4 >>  8) & (__u8)0xFFu;
	dst->s6_addr[q4] =  addr4        & (__u8)0xFFu;
}

int rfc6052_4to6(struct xlation *state,
		const struct in_addr *src,
		struct in6_addr *dst)
{
	struct ipv6_prefix *prefix = &state->GLOBAL.pool6;

	memcpy(dst, &prefix->addr, sizeof(*dst));

	switch (prefix->len) {
	case 96:  /* First because it's the most common one, I guess. */
		dst->s6_addr32[3] = src->s_addr;
		return 0;
	case 32:
		dst->s6_addr32[1] = src->s_addr;
		return 0;
	case 40:
		__addr_4to6(src, dst, 5, 6, 7, 9);
		return 0;
	case 48:
		__addr_4to6(src, dst, 6, 7, 9, 10);
		return 0;
	case 56:
		__addr_4to6(src, dst, 7, 9, 10, 11);
		return 0;
	case 64:
		__addr_4to6(src, dst, 9, 10, 11, 12);
		return 0;
	case 0:
		log_debug("pool6 hasn't been configured.");
		return esrch(state, JOOL_MIB_POOL6_NULL);
	}

	/*
	 * Critical because enforcing valid prefixes is global's responsibility,
	 * not ours.
	 */
	WARN(true, "Prefix has an invalid length: %u.", prefix->len);
	return einval(state, JOOL_MIB_UNKNOWN4);
}
