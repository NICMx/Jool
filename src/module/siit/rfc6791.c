#include "siit/rfc6791.h"

static void randomize_host(__u8 *prefix_addr, unsigned int prefix_len,
		int addr_len, __u8 *result)
{
	/** Number of *full* network-side "quadrants" (8-bit segments). */
	unsigned int segment_bytes_num;
	unsigned int modulus;
	unsigned int offset;
	/** Number of quadrants that have at least one host bit. */
	size_t host_bytes_num;
	__u8 randomized_byte;

	segment_bytes_num = prefix_len >> 3; /* >> 3 = / 8 */
	modulus = prefix_len & 7; /* & 7 = % 8 */
	offset = segment_bytes_num;
	host_bytes_num = addr_len - segment_bytes_num;

	memcpy(result, prefix_addr, prefix_len);

	if (modulus == 0) {
		get_random_bytes(((__u8*)result) + offset, host_bytes_num);
		return;
	}

	get_random_bytes(((__u8*)result) + offset + 1, host_bytes_num - 1);
	get_random_bytes(&randomized_byte, sizeof(randomized_byte));

	randomized_byte &= (1 << (8 - modulus)) - 1;
	result[segment_bytes_num] |= randomized_byte;
}

static void pop_addr4(struct ipv4_prefix *prefix, __be32 *result)
{
	return randomize_host((__u8 *)&prefix->addr, prefix->len, 4,
			(__u8 *)result);
}

int rfc6791_find4(struct xlation *state, __be32 *result)
{
	struct config_prefix4 *prefix = &GLOBAL_GET(state, rfc6791_prefix4);

	if (prefix->set) {
		pop_addr4(&prefix->prefix, result);
		return 0;
	}

	return einval(state, JOOL_MIB_6791V4_EMPTY); /* TODO pick host addr */
}

/**
 * Assuming RFC6791v6 has been populated, returns an IPv6 address an ICMP
 * error should be sourced with, assuming its source is untranslatable.
 */
static void pop_addr6(struct ipv6_prefix *prefix, struct in6_addr *result)
{
	return randomize_host(&prefix->addr.s6_addr[0], prefix->len, 16,
			(__u8 *)result);
}

/**
 * Returns an IPv6 address an ICMP error should be sourced with, assuming its
 * source is untranslatable.
 */
int rfc6791_find6(struct xlation *state, struct in6_addr *result)
{
	struct config_prefix6 *prefix = &GLOBAL_GET(state, rfc6791_prefix6);

	if (prefix->set) {
		pop_addr6(&prefix->prefix, result);
		return 0;
	}

	return einval(state, JOOL_MIB_6791V6_EMPTY); /* TODO pick host addr */

/* TODO
success:
	log_debug("Chose %pI6c as RFC6791v6 address.", result);
	return 0;
*/
}
