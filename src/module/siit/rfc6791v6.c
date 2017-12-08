#include "siit/rfc6791v6.h"

#include <linux/random.h>
#include <net/addrconf.h>
#include "config.h"
#include "packet.h"
#include "rcu.h"
#include "route.h"
#include "tags.h"

/**
 * Assuming RFC6791v6 has been populated, returns an IPv6 address an ICMP
 * error should be sourced with, assuming its source is untranslatable.
 */
static int get_rfc6791_address_v6(struct xlation *state,
		struct in6_addr *result)
{
	struct ipv6_prefix *prefix;
	unsigned int segment_bytes_num;
	unsigned int modulus;
	unsigned int offset;
	size_t host_bytes_num;
	__u8 randomized_byte;

	if (!state->jool.global->cfg.siit.use_rfc6791_v6)
		return -EINVAL;

	prefix = &state->jool.global->cfg.siit.rfc6791_v6_prefix;

	segment_bytes_num = prefix->len >> 3; /* >> 3 = / 8 */
	modulus = prefix->len & 7; /* & 7 = % 8 */
	offset = segment_bytes_num;
	host_bytes_num = 16 - segment_bytes_num;

	(*result) = prefix->address;

	if (modulus == 0) {
		get_random_bytes(((__u8*)result) + offset, host_bytes_num);
		return 0;
	}

	get_random_bytes(((__u8*)result) + offset + 1, host_bytes_num - 1);
	get_random_bytes(&randomized_byte, sizeof(randomized_byte));

	randomized_byte &= (1 << (8 - modulus)) - 1;
	result->s6_addr[segment_bytes_num] |= randomized_byte;

	return 0;
}

/**
 * Assuming RFC6791v6 has not been populated, returns an IPv6 address an ICMP
 * error should be sourced with, assuming its source is untranslatable.
 */
static int get_host_address_v6(struct xlation *state, struct in6_addr *result)
{
	struct in6_addr *daddr;
	unsigned int flags;

	daddr = &pkt_ip6_hdr(&state->out)->daddr;
	flags = IPV6_PREFER_SRC_PUBLIC;

	if (ipv6_dev_get_saddr(state->jool.ns, NULL, daddr, flags, result)) {
		log_warn_once("Can't find a sufficiently scoped primary source address to reach %pI6.",
				daddr);
		return -EINVAL;
	}

	return 0;
}

/**
 * Returns an IPv6 address an ICMP error should be sourced with, assuming its
 * source is untranslatable.
 */
int rfc6791_find_v6(struct xlation *state, struct in6_addr *result)
{
	int error;

	error = get_rfc6791_address_v6(state, result);
	if (!error)
		goto success;

	error = get_host_address_v6(state, result);
	if (error)
		return error;

	/* Fall through. */

success:
	log_debug("Chose %pI6c as RFC6791v6 address.", result);
	return 0;
}
