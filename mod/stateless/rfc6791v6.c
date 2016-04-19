#include "nat64/mod/stateless/rfc6791v6.h"

#include <linux/inet.h>
#include <linux/in_route.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/random.h>
#include <net/ip_fib.h>
#include <net/addrconf.h>

#include "nat64/mod/common/config.h"
#include "nat64/mod/common/packet.h"
#include "nat64/mod/common/rcu.h"
#include "nat64/mod/common/route.h"
#include "nat64/mod/common/tags.h"


/**
 * Returns in "result" the IPv6 address an ICMP error towards "out"'s
 * destination should be sourced with.
 */
static int get_rfc6791_address_v6(struct xlation *state, struct in6_addr *out_result)
{
	struct ipv6_prefix prefix;

	__u8 host_bytes_num;
	__u8 segment_bytes_num;
	__u8 modulus;
	__u8 randomized_byte = 0;
	__u8 offset;
	int i = 0;

	if (state->jool.global->cfg.siit.use_rfc6791_v6) {

		prefix  = state->jool.global->cfg.siit.rfc6791_v6_prefix;

		host_bytes_num = ((__u8)128 - prefix.len) / (__u8)8;
		segment_bytes_num = (__u8)16 - host_bytes_num;
		modulus = prefix.len % 8;

		(*out_result) = prefix.address;

		offset = segment_bytes_num;

		if (modulus != 0)
			offset++;

		get_random_bytes(((__u8*)out_result) + offset, host_bytes_num);

		if (modulus != 0) {

			get_random_bytes(&randomized_byte, 1);

			for (i = 0; i < modulus ; i--) {
				randomized_byte &= ~(1 << (7-i));
			}

			*(((__u8*)out_result)+segment_bytes_num) = *(((__u8*)out_result)+segment_bytes_num) | randomized_byte;
		}

		return 0;
	}

	return -EINVAL;
}

/**
 * Returns in "result" the IPv4 address an ICMP error towards "out"'s
 * destination should be sourced with, assuming the RFC6791 pool is empty.
 */
static int get_host_address_v6(struct xlation *state, struct in6_addr *result)
{
	struct ipv6hdr * hdr;
	struct in6_addr saddr;
	struct in6_addr daddr;


	hdr = pkt_ip6_hdr(&state->out);
	daddr = hdr->daddr;


	if (ipv6_dev_get_saddr(state->jool.ns, NULL, &daddr, IPV6_PREFER_SRC_PUBLIC, &saddr)) {

		log_warn_once("Can't find a sufficiently scoped primary source "
				"address to reach %pI6.", &daddr);
		return -EINVAL;
	}

	*result = saddr;
	return 0;
}


int rfc6791_find_v6(struct xlation *state, struct in6_addr *result)
{

	int error;

	error = get_rfc6791_address_v6(state, result);

	if (!error) {
		//TODO delete this, it's used just for testing purpose
			log_info("RFC6791V6 - Random address successfully obtained!");
			log_info("RFC6791V6 - Address : %pI6", result);
		return 0;
	}

	//TODO delete this, it's used just for testing purpose
	log_info("RFC6791V6 - Using host address instead of a Random One!");

	error = get_host_address_v6(state, result);

	if (error) {
		log_info("RFC6791V -- Error while obtaining host address!");
		return error;
	}

	//TODO delete this, it's used just for testing purpose
	log_info("RFC6791V6 - Host address successfully obtained!");
	log_info("RFC6791V6 - Address : %pI6", result);


	return 0;
}

